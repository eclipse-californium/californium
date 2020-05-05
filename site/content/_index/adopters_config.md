+++
fragment = "config"

[[config]]
  type = "css" # Acceptable values are icon, meta, link, css, js. Default is empty. Would not add anything on empty.
  # block = true # If set to true, would inject the code to the <head> tag. Default is false
  resource = "css/adopters.css"

[[config]]
  type = "js"
  block = false # put script tag at the end of <body>
  resource = "https://iot.eclipse.org/assets/js/eclipsefdn.adopters.js"
+++
