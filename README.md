## Introduction
The Falco Plugin for Box ingests *Enterprise Events* from Box and makes them available as fields in Falco.  With the Box Enterprise Event fields available in Falco, you can create Falco rules to detect Box threats in real-time, and alert on them through your configured notification channel. You can find more about Box Enterprise Events [here](https://developer.box.com/guides/events/enterprise-events/) 

**What's the value in ingesting Box events into Falco?**

Well - because Falco can perform threat detection across a number of cloud platforms in parallel, it allows you to correlate security events across multiple sources in real-time, to detect active lateral movement as it is occurring.

## Prerequisites

1. The plugin needs to compile with a minimum of Go version 1.20
2. Accessing *Enterprise Events* requires a Box *Enterprise* or *Enterprise Plus* subscription.
3. The plugin authenticates using 2-Legged oAuth so you need to create a Custom App and get the client id and secret - see below.
4. (Optional) Access to a Maxmind GeoLite or GeoIP2 database to enrich IP addresses with Geolocation information
  

### Create App in Box Developer Console
To allow Falco to communicate with Box via 2-Legged oAuth, a *Custom App* must be created in the Developer Console of your account - you can access the Developer Console [here](https://app.box.com/developers/console).  Once logged in to the Developer Console, follow the following steps.

1.  Click on *My Apps* then on the *Create New App* button on the right side of the screen
2.  Select *Custom App* section as your application type
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/56c77512-e2cd-4ca9-b4bc-10fe52d94604" style="display: block;margin-left:50px" height="300" /></dd>
</dl>
   
3.  Complete the *App Name* and *Description* section
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/41ea277f-887b-466a-9b18-e957f73310bb"  width="400" /></dd>
</dl>

4.  Complete the other integration sections and click Next
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/dafd58d4-243b-41ef-9406-b912d9c3f055" width="400" /></dd>
</dl>

5.  Select *Server Authentication (Client Credentials Grant)* and click *Create App*
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/4289717a-5f46-441f-b741-0a77ad4dfef7" width="400" /></dd>
</dl>
   
6.  You will be taken to the application configuration page
7.  Scroll down to the *OAuth 2.0 Credentials* section take note of your ***Client ID***.  Click *Fetch Client Secret* to display your ***Client Secret***
8.  Scroll down to the *App Access Level* section and select *App + Enterprise Access*
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/bc325d25-c174-449f-8a70-f6117e789765" width="400" /></dd>
</dl>
   
9.  Scroll down to the *Application Scopes* section and uncheck all scopes except ***Manage Enterprise Properties***
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/9eb4f197-8bf1-4408-9e19-bf2860a2621f" width="400" /></dd>
</dl>
  
10. Click the *Save Changes Button* in the top right of the screen
11. Click on the *Authorization* tab and click the *Review and Submit* button
<dl>
<dd><img src="https://github.com/an1245/falco-plugin-box/assets/127995147/e480d666-cc15-4f09-853e-aa54553db5cc" width="400" /></dd>
</dl>

12. Contact your Box administrator and request that they approve the application
13. Finally - navigate to your *Account Billing* section into Box Administrator portal [here](https://app.box.com/master/settings/accountBilling) and take note of your ***Enterprise ID***

### Download Maxmind City Database for IP Geolocation enrichment
The plugin has the ability to enrich IP addresses with geolocation information using the Maxmind GeoLite (free) or GeoIP2 (commercial) databases. You can register for Maxmind databases [here](https://www.maxmind.com/en/geolite2/signup).   Once you have downloaded the ***Maxmind City Database*** in mmdb format, store it somewhere on the file system where Falco can access it.  

You can then configure the plugin to use the database by configuring the *maxmindcitydbpath* option in *falco.yaml*. See *Configuring the plugin* section below.


## Building the Box plugin
1. Download the plugin from GitHub using git
2. Change directory to falco-plugin-box
3. Compile the plugin using *make*
4. Copy *libbox.so* to */usr/share/falco/plugins*
5. Copy the rules to /etc/falco/rules.d/
```
git clone https://github.com/an1245/falco-plugin-box
cd falco-plugin-box
make
cp libbox.so /usr/share/falco/plugins/
cp rules/* /etc/falco/rules.d/
```

## Configuring the plugin
Now that you have collected your ***Client ID***, ***Client Secret*** and ***Enterprise ID***, you can provide them as values in the falco.yaml file.  
```
- name: box
    library_path: libbox.so
    init_config:
      boxclientid: (your client id)
      boxclientsecret: (your client secret)
      boxenterpriseid: (your enterprise id) 
      maxmindcitydbpath: (path to your geolite database)/GeoLite2-City.mmdb
      Debug: False
      DebugLevel: 0
      PollIntervalSecs: 300
```

Now that you've got the plugin configuration done, you can enable it by adding the plugin name to the *load_plugins* configuration setting.
```
load_plugins: [box]
```

## Debugging the Plugin

We recommend leaving Debug set to False unless you are trying to troubleshoot the plugin.  

But if you need to troubleshoot the plugin, you set ***Debug: True***, ***DebugLevel*** to a value from 0-4, and then run ***falco*** manually from the command line - this will output debug messages to  STDOUT.  As you increase the ***DebugLevel***,  the verbosity of the debug logging will increase. 

## Box Admin Event Streaming API

The plugin polls the Box Admin Event Streaming API, parsing and mapping the Box event fields onto Falco plugin fields that can be evaluated and aleted by Falco.  The plugin uses the *admin_logs_streaming* logs stream type, collecting events from the time you start the plugin onwards - it does not collect/parse the 2 weeks of historical events held within this stream.  

You can find out more about the Box Enterprise Events and Event Types [here](https://developer.box.com/guides/events/enterprise-events/for-enterprise/)

The Box *Event Type* field is mapped directly onto the Falco Box Plugin *box.eventtype* field.

## Polling Frequency and Box API Rate Limits

The plugin polls the API every 300 seconds by default.  You can decrease or increase the polling frequency by changing the *PollIntervalSecs* setting in *falco.yaml*.  **Please NOTE** - this may have impacts on your costs - keep reading..

Box limits the number of API calls to protect their service from issues and ensure quality of service - the limits vary based your licensing type and the API you are calling.
You can find more information on Box API limits in the following web pages.

Box API Rate Limits: https://developer.box.com/guides/api-calls/permissions-and-errors/rate-limits/

Box API Rate Limits per Account Type: https://www.box.com/pricing

Please contact your Box representative for more information.

## Default Rules

You can find a number of sample Falco rules in the *rules/box.yaml* file which will detect a number of malicious events including:

- Successful user logins(for auditing)
- Failed user logins
- Logins by Administrator users
- Logins from foreign countries or geographies
- Disabling of MFA, or Failed MFA token responses
- Creation and revocation of oAuth access tokens
- A number of other threats identified by Box Shield

Here are two tips for creating your own rules.

1. Box doesn't currently provide documentation for each events JSON response document; however, there is a rule in *rules/box.yaml* called ***Box - Catch Everything Else*** - it's commented out by default to reduce noise, but you can enable this rule to alert on every Box Event not captured by another rule and output all the mapped fields.

2. You can also set the ***DebugLevel*** to 1 and can see how the Box fields are mapped to Falco fields by observing the *Falco Event JSON:* log message.  

## Exported Fields

A number of fields are mapped across from Box event fields into Falco fields - these can be seen in the table below.

| Field Name | Type | Description |
| ----------- | ----------- |  ----------- |
| box.access_token_id | string | Access Token ID for an object that has been accessed |
| box.eventid | string | Box Event Identifier |
| box.eventtype | string | Type of Box event (ex. ADMIN_LOGIN event) |
| box.city | string | The city where the users IP address is physically located |
| box.created_by_name | string | The name of the user that initiated the action which generated this event  |
| box.created_by_login | string | The login of the user that initiated the action which generated this event |
| box.created_by_id | string | The ID of the user that initiated the action which generated this event |
| box.country | string | The country where the users IP address is physically located |
| box.countryisocode | string | The country ISO code where the users IP address is physically located |
| box.continent | string | The continent where the users IP address is physically located |
| box.ekm_id | string | The EKM ID of the object that has been accessed |
| box.ipaddress | string | The IP address of the user that created the event |
| box.messagetype | string | What type of Box Message was received? (ex. event message) |
| box.servicename | string | The name of the Box Service that this event is associated with |
| box.serviceid | string | The ID of the Box Service that this event is associated with |
| box.shieldalert | string | Alert description sent through as part of a Shield Alert |
| box.size | string | The size of the object that has been accessed |
| box.sourceitemtype | string | Type of the item that a user is reading |
| box.sourceitemid | string | ID of the item that a user is reading |
| box.sourceitemname | string | Name of the item that a user is reading |
| box.userid | string | The id of the user the action has been taken against  |
| box.username | string | The username of the user the action has been taken against |
| box.userlogin | string | The login of the user the action has been taken against |
| box.timestamp | string | The timestamp when the event occurred |
| box.versionid | string | The version id of the object that was accessed |

## Feedback

Please provide me with feedback if you think there are better ways I could do things - you can do that by starting a discussion or logging an issue! 

I have tested this plugin against a Box Developer Account which has a low amount of activity - there could be tweaks that need to be made in larger environments.  I am particularly interested in feedback on:

1.  Polling Interval being set to 300 seconds (5 mins) - does this correctly balance timely delivery of events without overconsuming API calls?

2. At this point I do not filter the events coming from the API - I wanted to give you the freedom to build rules against the entire set of Box events.  If consuming all the events is too heavy, I will filter the events at source to make it lighter.  Please give me feedback!

## Thanks

Thanks to the folks who helped out with this plugin.
