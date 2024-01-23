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

package maxminddb

import (
	"log"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Ipinfo struct {
	IP        string
	City      string
	Country   string
	Continent string
	Isocode   string
	Timezone  string
	Longitude float64
	Latitude  float64
}

func GetIPLocation(ipstr string, citydbpath string, countrydbpath string, asndbpath string, debug bool) Ipinfo {

	tempipinfo := Ipinfo{}

	if len(citydbpath) > 0 {
		db, err := geoip2.Open(citydbpath)
		if err != nil {
			if debug {
				log.Fatal(err)
			}
		}
		defer db.Close()

		ip := net.ParseIP(ipstr)
		city, err := db.City(ip)
		if err != nil {
			if debug {
				log.Fatal(err)
			}
		}

		tempipinfo.IP = ipstr
		tempipinfo.City = city.City.Names["en"]
		tempipinfo.Country = city.Country.Names["en"]
		tempipinfo.Isocode = city.Country.IsoCode
		tempipinfo.Timezone = city.Location.TimeZone
		tempipinfo.Latitude = city.Location.Latitude
		tempipinfo.Longitude = city.Location.Longitude
		tempipinfo.Continent = city.Continent.Names["en"]
	}

	return tempipinfo

}
