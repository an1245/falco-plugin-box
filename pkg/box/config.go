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

// PluginConfig represents a configuration of the GitHub plugin
type PluginConfig struct {
	BoxClientId       string `json:"boxclientid" jsonschema:"title=Box Custom App Client Id"`
	BoxClientSecret   string `json:"boxclientsecret" jsonschema:"title=Box Custom App Client Secret"`
	BoxEnterpriseID   int64  `json:"boxenterpriseid" jsonschema:"title=Box Enterprise ID"`
	MaxmindCityDBPath string `json:"maxmindcitydbpath" jsonschema:"title=Path to Maxmind GeoLite2 or GeoIP2 City Database"`
	Debug             bool   `json:"Debug" jsonschema:"title=Enable debug output (true = yes, false=no)"`
	DebugLevel        int    `json:"DebugLevel" jsonschema:"title=What Debug Level is set (0=INFO,)"`
	PollIntervalSecs  int    `json:"PollIntervalSecs" jsonschema:"title=How often do you want to poll the API?"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {

}
