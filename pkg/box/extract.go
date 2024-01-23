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
	"fmt"
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

// Return the fields supported for extraction.
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "box.access_token_id", Display: "Access Token ID", Desc: "Access Token ID"},
		{Type: "string", Name: "box.eventid", Display: "Event Id", Desc: "The Box Event Identifier"},
		{Type: "string", Name: "box.eventtype", Display: "Event Type", Desc: "The type of Box event (example. LoginEvent)"},
		{Type: "string", Name: "box.city", Display: "City", Desc: "The city where the user’s IP address is physically located"},
		{Type: "string", Name: "box.created_by_name", Display: "Event created by user name", Desc: "Which user name created the event"},
		{Type: "string", Name: "box.created_by_login", Display: "Event created by user login", Desc: "Which user login created the event"},
		{Type: "string", Name: "box.created_by_id", Display: "Event created by user id", Desc: "Which user id created the event"},
		{Type: "string", Name: "box.country", Display: "Country", Desc: "The country where the user’s IP address is physically located"},
		{Type: "string", Name: "box.countryisocode", Display: "Country ISO Code", Desc: "The country iso code where the user’s IP address is physically located"},
		{Type: "string", Name: "box.continent", Display: "Continent", Desc: "The continent where the user’s IP address is physically located"},
		{Type: "string", Name: "box.ekm_id", Display: "EKM ID", Desc: "Box EKM ID"},
		{Type: "string", Name: "box.ipaddress", Display: "IP address", Desc: "The IP address of the client that is logged in"},
		{Type: "string", Name: "box.messagetype", Display: "Message Type", Desc: "What type of Box Message was received? (i.e. event message)"},
		{Type: "string", Name: "box.servicename", Display: "Service Name", Desc: "The name of the service the event is related to"},
		{Type: "string", Name: "box.serviceid", Display: "Service ID", Desc: "The ID of the service the event is related to"},
		{Type: "string", Name: "box.shieldalert", Display: "Shield Alert", Desc: "Shield Alert"},
		{Type: "string", Name: "box.size", Display: "Object Size", Desc: "Size of the object"},
		{Type: "string", Name: "box.sourceitemtype", Display: "Item Type", Desc: "Type of the item that has been accessed"},
		{Type: "string", Name: "box.sourceitemid", Display: "Item ID", Desc: "ID of the item that has been accessed"},
		{Type: "string", Name: "box.sourceitemname", Display: "Item Name", Desc: "Name of the item that has been accessed"},
		{Type: "string", Name: "box.userid", Display: "User ID", Desc: "The ID of the user logging in"},
		{Type: "string", Name: "box.username", Display: "Username", Desc: "The username of the user logging in"},
		{Type: "string", Name: "box.userlogin", Display: "User Login", Desc: "The login name of the user loggin in"},
		{Type: "string", Name: "box.timestamp", Display: "Event Timestamp", Desc: "Timestamp that the event happened"},
		{Type: "string", Name: "box.versionid", Display: "Object Version", Desc: "Version of the object"},
		{Type: "string", Name: "box.pluginerrormessage", Display: "Plugin Error Message", Desc: "Plugin Error Message"},
	}
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "box.access_token_id":
		res = string(jdata.GetStringBytes("Access_Token_ID"))
	case "box.eventid":
		res = string(jdata.GetStringBytes("EventID"))
	case "box.eventtype":
		res = string(jdata.GetStringBytes("EventType"))
	case "box.city":
		res = string(jdata.GetStringBytes("City"))
	case "box.country":
		res = string(jdata.GetStringBytes("Country"))
	case "box.continent":
		res = string(jdata.GetStringBytes("Continent"))
	case "box.created_by_name":
		res = string(jdata.GetStringBytes("Created_By_Name"))
	case "box.created_by_login":
		res = string(jdata.GetStringBytes("Created_By_Login"))
	case "box.created_by_id":
		res = string(jdata.GetStringBytes("Created_By_ID"))
	case "box.ekm_id":
		res = string(jdata.GetStringBytes("EKM_ID"))
	case "box.messagetype":
		res = string(jdata.GetStringBytes("Type"))
	case "box.ipaddress":
		res = string(jdata.GetStringBytes("IPAddress"))
	case "box.servicename":
		res = string(jdata.GetStringBytes("Service_Name"))
	case "box.serviceid":
		res = string(jdata.GetStringBytes("Service_ID"))
	case "box.sheildalert":
		res = string(jdata.GetStringBytes("Shield_Alert"))
	case "box.size":
		res = string(jdata.GetStringBytes("Size"))
	case "box.sourceitemtype":
		res = string(jdata.GetStringBytes("Source_Item_Type"))
	case "box.sourceitemid":
		res = string(jdata.GetStringBytes("Source_Item_ID"))
	case "box.sourceitemname":
		res = string(jdata.GetStringBytes("Source_Item_Name"))
	case "box.userid":
		res = string(jdata.GetStringBytes("Source_ID"))
	case "box.username":
		res = string(jdata.GetStringBytes("Source_Name"))
	case "box.userlogin":
		res = string(jdata.GetStringBytes("Source_Login"))
	case "box.timestamp":
		res = string(jdata.GetStringBytes("Timestamp"))
	case "box.versionid":
		res = string(jdata.GetStringBytes("VersionId"))
	case "box.pluginerrormessage":
		res = string(jdata.GetStringBytes("PluginErrorMessage"))
	default:
		return false, ""
	}

	return true, res
}

// Extract a field value from an event.
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := io.ReadAll(evt.Reader())
		if err != nil {
			return fmt.Errorf("Box Plugin ERROR: Couldn't read event from Event Reader in Extract - %v", err)
		}

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return fmt.Errorf("Box Plugin ERROR: Couldn't parse JSON in Extract - %v", err)
		}
		p.jdataEvtnum = evt.EventNum()
	}

	// Extract the field value
	present, value := getfieldStr(p.jdata, req.Field())
	if present {
		req.SetValue(value)
	}

	return nil
}
