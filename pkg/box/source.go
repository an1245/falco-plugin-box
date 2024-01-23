// SPDX-License-Identifier: Apache-2.0
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package box

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"time"

	"golang.org/x/oauth2"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/oauth2/clientcredentials"
)

var (
	// topic and subscription-related variables
	BoxTokenURL = "https://api.box.com/oauth2/token"
)

func (p *Plugin) initInstance(oCtx *PluginInstance) error {

	// think of plugin_init as initializing the plugin software

	oCtx.boxChannel = nil
	return nil

}

// Open an event stream and return an open plugin instance.
func (p *Plugin) Open(params string) (source.Instance, error) {

	// think of plugin_open as configuring the software to return events

	// Allocate the context struct for this open instance
	oCtx := &PluginInstance{}
	err := p.initInstance(oCtx)
	if err != nil {
		return nil, err
	}

	if p.config.Debug {
		log.Printf("Box Plugin: Debug logging is enabled at Debug Level: " + fmt.Sprintf("%d", p.config.DebugLevel))
	}

	// Create the channel
	oCtx.boxChannel = make(chan []byte, 128)

	// Launch the APIClient
	go fetchAuditAPI(p, oCtx, oCtx.boxChannel)

	return oCtx, nil
}

// Closing the event stream and deinitialize the open plugin instance.
func (oCtx *PluginInstance) Close() {
	println("Box Plugin: Closing Maxmind DB")
	oCtx.geodb.Close()
}

// Produce and return a new batch of events.
func (o *PluginInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// Casting to our plugin type
	p := pState.(*Plugin)

	// Batching is not supported for now, so we only write the first entry of the batch
	evt := evts.Get(0)
	writer := evt.Writer()

	// Receive the event from the webserver channel with a 1 sec timeout
	var boxData []byte

	afterCh := time.After(1 * time.Second)
	select {
	case boxData = <-o.boxChannel:
		// Process data from box channel
		written, err := writer.Write(boxData)
		if err != nil {
			return 0, fmt.Errorf("Box Plugin ERROR: Couldn't write Box Event data events - %v", err)
		}
		if written < len(boxData) {
			return 0, fmt.Errorf("Box Plugin ERROR: Box message too long: %d, max %d supported", len(boxData), written)
		}

	case <-afterCh:
		p.jdataEvtnum = math.MaxUint64
		return 0, sdk.ErrTimeout
	}

	// Let the engine timestamp this event. It would probably be better to
	// use the updated_at field in the json.
	// evt.SetTimestamp(...)

	return 1, nil
}

type ErrorMessage struct {
	EventType          string
	PluginErrorMessage string
}

func breakOut(backoffcount int, Debug bool, errorMessage string, oCtx *PluginInstance) bool {
	// This function does back off processing - it will back off all the way out to 24 hours before exiting

	// Log a Debug Error Message
	if Debug {
		log.Print(errorMessage)
	}

	// Now work a back off
	errorCount := 40
	if backoffcount > errorCount {
		if Debug {
			log.Printf("Box Plugin ERROR: Error persisted for ages... - exiting")
		}

		// Start: Send an alert to Falco
		errorMessage = "Box Plugin ERROR: Error persisted for ages... - exiting"
		falcoalert := ErrorMessage{"pluginerror", errorMessage}
		falcoalertjson, err := json.Marshal(falcoalert)
		if err != nil {
			log.Printf("Box Plugin Error - breakOut(): Couldn't Create Plugin Error JSON")
		}
		oCtx.boxChannel <- falcoalertjson
		// End: Send an alert to Falco

		return false
	}
	if Debug {
		log.Printf("Box Plugin WARNING: error occurred while connecting to API - sleeping for %d min", backoffcount*5)
	}

	// Start: Send an alert to Falco
	errorMessage = errorMessage + " - sleeping for " + fmt.Sprintf("%d", (backoffcount*5)) + " mins."
	falcoalert := ErrorMessage{"pluginerror", errorMessage}
	falcoalertjson, err := json.Marshal(falcoalert)
	if err != nil {
		log.Printf("Box Plugin Error - breakOut(): Couldn't Create Plugin Error JSON")
	}
	oCtx.boxChannel <- falcoalertjson
	// End: Send an alert to Falco

	// Back off for a while
	time.Sleep(time.Duration(backoffcount*5) * time.Minute)
	return true
}

func fetchAuditAPI(p *Plugin, oCtx *PluginInstance, channel chan []byte) {
	backoffcount := 1

	// Outerloop is used for the backoff processing
	// after timeout, it continues this loop essentially restarting the whole process
outerloop:
	for {
		if p.config.Debug && p.config.DebugLevel >= 0 {
			log.Printf("Box Plugin - Starting Admin Event requester")
		}

		// Authenticate with Two-Legged oAuth and return a token source
		boxTokenSource, err := boxoAuthTokenSource(p.config.BoxClientId, p.config.BoxClientSecret, p.config.BoxEnterpriseID, p.config.Debug, p.config.DebugLevel)
		if err != nil {

			errorMessage := "Box Plugin ERROR: could not authenticate - check your Client ID, Secret and Enterprise ID in falco.yaml - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}

		}

		// Use Token source to get an authenticated HTTP Client
		boxClient, err := boxoAuthClient(boxTokenSource)
		if err != nil {

			errorMessage := "Box Plugin ERROR: could not retrieve box-authenticated HTTP client - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}

		}

		// First thing we need to do is grab the stream position so we don't have to parse historical events.
		// Start Stream Position
		if p.config.Debug && p.config.DebugLevel >= 0 {
			println("Box Plugin: Connecting to Box API to collect next_stream_position")
		}

		httpResponse, err := boxClient.Get("https://api.box.com/2.0/events?stream_type=admin_logs_streaming&stream_position=now")
		if err != nil || httpResponse.StatusCode != 200 {
			errorMessage := "Box Plugin ERROR: Could not fetch initial Admin Streaming Logs Stream Position - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}

		}

		body, err := io.ReadAll(httpResponse.Body)
		if err != nil {
			errorMessage := "Box Plugin ERROR: Could not read HTTP Response body to get stream position - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}
		}

		var jsonResponse map[string]interface{}
		err = json.Unmarshal(body, &jsonResponse)
		if err != nil {
			errorMessage := "Box Plugin ERROR: Could not Unmarshall JSON Response to get stream position - " + string(err.Error())
			if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
				backoffcount += 1
				continue outerloop
			} else {
				os.Exit(1)
			}
		}

		// Grab the stream position - and get ready to start polling.
		stream_position := jsonResponse["next_stream_position"]

		if p.config.Debug && p.config.DebugLevel >= 1 {
			println("Box Plugin: Retrieved Next Stream Position:" + fmt.Sprintf("%v", stream_position.(float64)))
		}
		// End Stream Position

		// Start: Open Maxmind Geo DB
		checkGeoDB := false

		if len(p.config.MaxmindCityDBPath) > 0 {
			if _, err := os.Stat(p.config.MaxmindCityDBPath); err == nil {
				tempgeodb, err2 := geoip2.Open(p.config.MaxmindCityDBPath)
				if err2 != nil {
					checkGeoDB = false
					if p.config.Debug && p.config.DebugLevel >= 0 {
						println("Box Plugin: Located Maxmind DB at path at MaxmindCityDBPath, but couldn't open it. Disabling GeoDB enrichment")
					}
				} else {
					checkGeoDB = true
					oCtx.geodb = *tempgeodb
					if p.config.Debug && p.config.DebugLevel >= 0 {
						println("Box Plugin: Found Maxmind GeoDB and opened it successfully - enabling GeoDB enrichment")
					}

				}

			} else {
				if p.config.Debug && p.config.DebugLevel >= 0 {
					println("Box Plugin: Could not locate Maxmind DB as specified in MaxmindCityDBPath in falco.yaml. Disabling GeoDB enrichment")
				}
			}

		} else {
			if p.config.Debug && p.config.DebugLevel >= 0 {
				println("Box Plugin: MaxmindCityDBPath config setting was blank in falco.yaml. Disabling GeoDB enrichment")
			}
		}
		// End: Open Maxmind Geo DB

		if p.config.Debug && p.config.DebugLevel >= 0 {
			println("Box Plugin: Entering Polling loop with polling interval " + fmt.Sprintf("%d", p.config.PollIntervalSecs) + " seconds")
		}

		// Loop infinitely and poll API after sleeping for the pool interval
		for {

			// Sleep for the poll interval
			if p.config.Debug && p.config.DebugLevel >= 1 {
				println("Box Plugin: Sleeping for " + fmt.Sprintf("%d", p.config.PollIntervalSecs) + " seconds")
			}
			time.Sleep(time.Duration(p.config.PollIntervalSecs) * time.Second)
			if p.config.Debug && p.config.DebugLevel >= 1 {
				println("Box Plugin: Polling Admin Events API for stream position: " + fmt.Sprintf("%f", stream_position.(float64)))
			}

			// Get the events after stream_position
			// TODO: can filter events using &event_type= usage
			// url -i -X GET "https://api.box.com/2.0/events?stream_type=admin_logs_streaming&event_type=LOGIN,FAILED_LOGIN" -H "authorization: Bearer <ACCESS_TOKEN>"
			httpResponse, err := boxClient.Get("https://api.box.com/2.0/events?stream_type=admin_logs_streaming&stream_position=" + fmt.Sprintf("%f", stream_position.(float64)))
			if err != nil || httpResponse.StatusCode != 200 {
				errorMessage := "Box Plugin ERROR: Could not fetch initial Admin Streaming Logs - " + string(err.Error())
				if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
					backoffcount += 1
					continue outerloop
				} else {
					os.Exit(1)
				}

			}

			body, err := io.ReadAll(httpResponse.Body)
			if err != nil {
				errorMessage := "Box Plugin ERROR: Could not read HTTP Response body - " + string(err.Error())
				if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
					backoffcount += 1
					continue outerloop
				} else {
					os.Exit(1)
				}

			}

			var jsonResponse map[string]interface{}
			err = json.Unmarshal(body, &jsonResponse)
			if err != nil {
				errorMessage := "Box Plugin ERROR: Could not Unmarshall JSON Response - " + string(err.Error())
				if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
					backoffcount += 1
					continue outerloop
				} else {
					os.Exit(1)
				}

			}

			// Update stream position
			stream_position = jsonResponse["next_stream_position"]

			// Now enumerate the response and map it onto Falco fields.
			err = StringMapToBoxEvent(jsonResponse, p.config.Debug, p.config.DebugLevel, channel, checkGeoDB, oCtx.geodb)
			if err != nil {
				errorMessage := "Box Plugin ERROR: Issue mapping Box Event to Falco event - " + string(err.Error())
				if breakOut(backoffcount, p.config.Debug, errorMessage, oCtx) {
					backoffcount += 1
					continue outerloop
				} else {
					os.Exit(1)
				}

			}

			if p.config.Debug && p.config.DebugLevel >= 1 {
				println("Box Plugin: Retrieved Next Stream Position:" + fmt.Sprintf("%v", stream_position.(float64)))
			}

		}
	}

}

func boxoAuthTokenSource(clientid string, clientsecret string, enterprise_id int64, debug bool, debuglevel int) (oauth2.TokenSource, error) {

	// Reference: https://chromium.googlesource.com/external/github.com/golang/oauth2/+/refs/heads/master/clientcredentials/clientcredentials_test.go
	config := clientcredentials.Config{
		ClientID:       clientid,
		ClientSecret:   clientsecret,
		TokenURL:       BoxTokenURL,
		EndpointParams: url.Values{"box_subject_type": {"enterprise"}, "box_subject_id": {fmt.Sprintf("%d", enterprise_id)}},
	}

	tokensource := config.TokenSource(context.Background())

	return tokensource, nil

}

func boxoAuthClient(boxtoken oauth2.TokenSource) (*http.Client, error) {

	// Reference: https://reintech.io/blog/guide-to-go-x-oauth2-package-oauth2-authentication
	httpclient := oauth2.NewClient(context.Background(), boxtoken)
	httpclient.Timeout = time.Duration(30) * time.Second
	return httpclient, nil

}

type BoxEvent struct {
	Access_Token_ID  string
	EventType        string
	EventID          string
	City             string
	Country          string
	CountryIsoCode   string
	Continent        string
	Created_By_Type  string
	Created_By_ID    string
	Created_By_Name  string
	Created_By_Login string
	EKM_ID           string
	IPAddress        string
	Service_Name     string
	Service_ID       string
	Shield_Alert     string
	Size             string
	Source_ID        string
	Source_Name      string
	Source_Login     string
	Source_Type      string
	Source_Item_Type string
	Source_Item_ID   string
	Source_Item_Name string
	Source_Parent    string
	Source_Owned_By  string
	Type             string
	Timestamp        string
	VersionId        string
}

func StringMapToBoxEvent(data map[string]interface{}, Debug bool, DebugLevel int, channel chan []byte, checkGeoDB bool, geodb geoip2.Reader) error {
	// Function enumerates the JSON reponse and maps onto Falco fields.
	// The reason it's done this way is for a few reasons:
	// 1. there is no current documentation on the JSON Responses
	// 2. some of the field values return different value types - so it needs to be dynamic
	// 3. it's a bit more resilient - won't crash if the format changes.

	for key1, value1 := range data {

		switch key1 {

		// entries is an array with an array entry for each event
		case "entries":
			if Debug && DebugLevel >= 1 {
				println("Box Plugin: Processing Events inside Entries node")
			}
			if x, ok := value1.([]interface{}); ok {

				// iterate through each event in the array
				for eventarraynumber, eventarraymap := range x {
					if Debug && DebugLevel >= 2 {
						println("\nBox Plugin: Processing Events #:" + fmt.Sprintf("%d", eventarraynumber))
					}

					newBoxEvent := &BoxEvent{}

					for eventkey, eventvalue := range eventarraymap.(map[string]interface{}) {

						if Debug && DebugLevel >= 3 {
							println(" -- Processing Events Key:" + fmt.Sprintf("%s", eventkey))
						}

						// switch through the JSON fields and populate the Box Event struct
						switch eventkey {

						case "action_by":
							if Debug && DebugLevel >= 4 {
								println(" --- Processing Action By Event with value Type" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
							}
						case "additional_details":
							if _, ok := eventvalue.(map[string]interface{}); ok {
								for additional_details_key, additional_details_value := range eventvalue.(map[string]interface{}) {
									value := expandInterface(additional_details_value, Debug, DebugLevel)
									switch additional_details_key {
									case "service_id":
										newBoxEvent.Service_ID = value
									case "service_name":
										newBoxEvent.Service_Name = value
									case "size":
										newBoxEvent.Size = fmt.Sprintf("%v", value)
									case "version_id":
										newBoxEvent.VersionId = fmt.Sprintf("%v", value)
									case "ekm_id":
										newBoxEvent.EKM_ID = fmt.Sprintf("%v", value)
									case "access_token_identifier":
										newBoxEvent.Access_Token_ID = fmt.Sprintf("%v", value)
									case "shield_alert":
										newBoxEvent.Shield_Alert = fmt.Sprintf("%v", value)

									default:
										if Debug && DebugLevel >= 0 {
											println("Box Plugin WARNING: - StringMapToBoxEvent-additional_details: Unhandled Key Found: " + additional_details_key)
										}
									}

									if Debug && DebugLevel >= 4 {
										println(" --- Processing additional_details Key: " + fmt.Sprintf("%s", additional_details_key) + " with value: " + value)
									}
								}
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: additional_details value wasn't map[string]interface{}. It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "event_type":
							if _, ok := eventvalue.(string); ok {
								if Debug && DebugLevel >= 4 {
									println(" --- Processing Event Type Value:" + eventvalue.(string))
								}
								newBoxEvent.EventType = eventvalue.(string)
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: event_type value wasn't eventvalue.(string). It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "event_id":
							if _, ok := eventvalue.(string); ok {
								if Debug && DebugLevel >= 4 {
									println(" --- Processing Event ID Event Value:" + eventvalue.(string))
								}
								newBoxEvent.EventID = eventvalue.(string)
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: event_id value wasn't eventvalue.(string). It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "created_at":
							if _, ok := eventvalue.(string); ok {
								if Debug && DebugLevel >= 4 {
									println(" --- Processing Created At Event Value:" + eventvalue.(string))
								}
								newBoxEvent.Timestamp = eventvalue.(string)
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: created_at value wasn't eventvalue.(string). It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "created_by":
							if _, ok := eventvalue.(map[string]interface{}); ok {
								for created_by_key, created_by_value := range eventvalue.(map[string]interface{}) {
									value := expandInterface(created_by_value, Debug, DebugLevel)
									switch created_by_key {
									case "type":
										newBoxEvent.Created_By_Type = value
									case "id":
										newBoxEvent.Created_By_ID = value
									case "name":
										newBoxEvent.Created_By_Name = value
									case "login":
										newBoxEvent.Created_By_Login = value
									default:
										if Debug && DebugLevel >= 0 {
											println("Box Plugin WARNING: - StringMapToBoxEvent-created_by: Unhandled Key Found: " + created_by_key)
										}
									}
									if Debug && DebugLevel >= 4 {
										println(" --- Processing Created_By Key: " + fmt.Sprintf("%s", created_by_key) + " with value: " + value)
									}
								}
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: created_at value wasn't map[string]interface{}. It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}

						case "ip_address":
							if _, ok := eventvalue.(string); ok {
								if Debug && DebugLevel >= 4 {
									println(" --- Processing IP Address Event Value:" + eventvalue.(string))
								}

								ipstr := eventvalue.(string)
								newBoxEvent.IPAddress = ipstr

								// enrich the IP address with Geo info
								if checkGeoDB && len(ipstr) > 0 {
									ip := net.ParseIP(ipstr)
									if ip != nil {
										city, err := geodb.City(ip)
										if err != nil {
											if Debug && DebugLevel >= 0 {
												println("Box Plugin WARNING: StringMapToBoxEvent: couldn't get City() for ip: " + ipstr)
											}
										}
										newBoxEvent.City = city.City.Names["en"]
										newBoxEvent.Country = city.Country.Names["en"]
										newBoxEvent.CountryIsoCode = city.Country.IsoCode
										newBoxEvent.Continent = city.Continent.Names["en"]
									}

								}
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: ip_address value wasn't eventvalue.(string). It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "session_id":
							if _, ok := eventvalue.(map[string]interface{}); ok {
								for session_id_key, session_id_value := range eventvalue.(map[string]interface{}) {
									value := expandInterface(session_id_value, Debug, DebugLevel)
									if Debug && DebugLevel >= 4 {
										println(" --- Processing session_id Key: " + fmt.Sprintf("%s", session_id_key) + " with value: " + value)
									}
								}
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: session_id value wasn't map[string]interface{}. It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "source":
							if _, ok := eventvalue.(map[string]interface{}); ok {
								for source_key, source_value := range eventvalue.(map[string]interface{}) {
									value := expandInterface(source_value, Debug, DebugLevel)
									switch source_key {
									case "type":
										newBoxEvent.Source_Type = value
									case "id":
										newBoxEvent.Source_ID = value
									case "name":
										newBoxEvent.Source_Name = value
									case "login":
										newBoxEvent.Source_Login = value
									case "item_type":
										newBoxEvent.Source_Item_Type = value
									case "item_id":
										newBoxEvent.Source_Item_ID = value
									case "item_name":
										newBoxEvent.Source_Item_Name = value
									case "parent":
										newBoxEvent.Source_Parent = value
									case "owned_by":
										newBoxEvent.Source_Owned_By = value
									default:
										if Debug && DebugLevel >= 0 {
											println("Box Plugin WARNING: StringMapToBoxEvent-source: Unhandled Key Found: " + source_key)
										}
									}

									if Debug && DebugLevel >= 4 {
										println(" --- Processing Source Key: " + fmt.Sprintf("%s", source_key) + " with value: " + value)
									}
								}
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: source value wasn't map[string]interface{}. It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						case "type":
							if _, ok := eventvalue.(string); ok {
								if Debug && DebugLevel >= 4 {
									println(" --- Processing Type Event Value:" + eventvalue.(string))
								}
								newBoxEvent.Type = eventvalue.(string)
							} else if eventvalue == nil {
							} else {
								if Debug && DebugLevel >= 0 {
									println("Box Plugin WARNING: StringMapToBoxEvent: source value wasn't eventvalue.(string). It was type:" + fmt.Sprintf("%v", reflect.TypeOf(eventvalue)))
								}
							}
						default:
							if Debug && DebugLevel >= 0 {
								println("Box Plugin WARNING: StringMapToBoxEvent: Unhandled Event Key:" + fmt.Sprintf("%s", eventkey))
							}

						}
					}

					// Now that we have processed the event message, create the JSON
					falcoEventJSON, err := json.Marshal(newBoxEvent)
					if err != nil {
						fmt.Printf("Box Plugin: WARNING - failed to marshall newBoxEvent to JSON  - %v", err)
					}

					// Send the Event JSON back to the Channel
					channel <- falcoEventJSON

					if Debug && DebugLevel >= 1 {
						println("Box Plugin - Falco Event JSON: " + string(falcoEventJSON))
					}
				}
			} else {
				println("Box Plugin WARNING: StringMapToBoxEvent: Unhandled value 1:" + string(key1))
			}
		case "next_stream_position":
			//nothing to do - not used at this stage - just here to ack that i've seen it

		case "chunk_size":
			//nothing to do - not used at this stage - just here to ack that i've seen it

		default:
			// if we get here, we haven't seen the key before and I need to write a handler for it.

			if Debug && DebugLevel >= 0 {
				println("Box Plugin WARNING: StringMapToBoxEvent: Unhandled Key 1:" + string(key1))
			}
		}
	}

	return nil
}

func expandInterface(interface_value interface{}, Debug bool, DebugLevel int) string {

	// Some of the fields have dynamic value types and so we need to carefully map them to avoid the code crashing.

	value := ""
	variabletype := fmt.Sprintf("%T", interface_value)
	switch interface_value.(type) {
	case string:
		value = interface_value.(string)
	case float64:
		value = fmt.Sprintf("%f", (interface_value.(float64)))
	case map[string]interface{}:

		if _, ok := interface_value.(map[string]interface{}); ok {
			value = "("
			for key1, value1 := range interface_value.(map[string]interface{}) {
				if Debug && DebugLevel >= 4 {
					println("Box Plugin WARNING: Processing Additional Key Map Inteface: " + key1)
				}
				switch value1.(type) {
				case string:
					value = value + string(key1) + "=" + string(value1.(string)) + ","
				case float64:
					value = value + string(key1) + "=" + fmt.Sprintf("%f", value1.(float64)) + ","
				case int:
					value = value + string(key1) + "=" + fmt.Sprintf("%d", value1.(int)) + ","
				default:
					value = "UNKOWN CONVERSION VALUE"
				}
			}
			value += ")"
		}

	default:
		// If we end up here - we haven't seen this type before and we need to write a processor

		if Debug && DebugLevel >= 0 {
			println("Box Plugin WARNING: ExpandInterface(): Unhandled Type conversion: " + variabletype)
		}
	}

	return value

}
