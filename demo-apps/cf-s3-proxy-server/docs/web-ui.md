![Californium logo](../../../cf_64.png)

# Californium (Cf) - Cloud CoAP-S3-Proxy Server

## Web UI

The WEb UI is implemented as Single Page Application in plain [javascript](../src/main/resources/app.js). That allows to use it from all devices, which comes with an modern web-browser.

On start, the login page asks for your web-login and internally returns the signing credentials to access the device data on S3. The protection mechanisms on S3 depends on the provider and not all have a fine-grained permission model. Therefore just a basic permission model with read and read/write rights based on S3 buckets is used.

### Web-Browser application login page:

![browser-login](./S3-proxy-login.png)

Enter the name and password and press "Login". If you're done, press "Logout".

### Web-Browser application device list page:

After the login the view is switching to the device list.

![browser-list](./S3-proxy-list.png)

Here you may switch the the begin of the list with `<<` or to the end with `>>`. With `<` and `>` you move the list one page to the begin or end of the list.

When the list is shown at the begin, clicking on the column titles, `Device`, `Last Update`, `Provider`, `Operator`, `Bd` (Band), `Uptime`, or `Bat.`, to sort the list according the values of that column. If you click again, the order is reverted.
Which columns are shown is configured an may vary from user to user.

If you `refresh` the list, updated entries will be shown with a yellow backgound.

![browser-list](./S3-proxy-list-new.png)

### Web-Browser application chart page:

![browser-chart](./S3-proxy-chart.png)

With the slidebar the displayed period is selected. Short periods up to 10 days may be selected by steps in single days, larger periods are selected in larger steps.

At the top of the chart several checkboxes are available. With `Signals` you select the technical values, battery voltage, battery level, signal level, signal quality, number of retransmissions, and RTT. With `Sensors` you get for a `Thingy:91` the temperature, air pressure and humidity. For other devices you may get other values. With `Average` and `Min/Max` you select, how multiple values are mapped into a single point. `Zoom` extends the value range to the full y-axis.

![browser-chart-signals](./S3-proxy-chart-signals.png))

### Web-Browser application device status page (from device):

![browser-status](./S3-proxy-status.png)

Web-Browser application device configuration page (to device):

![browser-config](./S3-proxy-config.png)

Web-Browser application server diagnose page:

![browser-diagnose](./S3-proxy-diagnose.png)