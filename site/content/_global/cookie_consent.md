+++
fragment = "config"

[[config]]
  type = "css" # Acceptable values are icon, meta, link, css, js. Default is empty. Would not add anything on empty.
  # block = true # If set to true, would inject the code to the <head> tag. Default is false
  resource = "https://www.eclipse.org/eclipse.org-common/themes/solstice/public/stylesheets/vendor/cookieconsent/cookieconsent.min.css"

[[config]]
  type = "js"
  block = true # put script tag at the end of <body>
  resource = "https://www.eclipse.org/eclipse.org-common/themes/solstice/public/javascript/vendor/cookieconsent/default.min.js"
+++
