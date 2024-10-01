---
description: DarkTrace Model Editor Cheatsheet, for creating and fine tuning your models.
hidden: true
---

# Model Editor Cheatsheet

### Creation

#### Tips

* Always disable auto suppress for new models.
* Always set the Breach Priority to "Informational" for new models.
* Always disable the Darktrace RESPOND for new models.

### Fine Tuning

### Breach firing

* By **Device** :
  * Breach Log -> Ignore Future Breaches
* By **Model field** :
  * Breach Log -> Add Model defeats -> Select specific field
* By **Device Tag :**
  * Useful if the behavior is normal for a specific type of device and we have a lot of such devices in our network. For example, a Security Device breaching a Network Scan.
  * Select device -> Edit device tags
* By **Domain**
  * Useful if the domain is rare, but it is considered legit for our purposes.
  * Configure Trusted Domains.
  * Use [https://\<darktrace\_hostname>/status?hostname=google.com](https:/%3Cdarktrace\_hostname%3E/status) lookup hostname scores from the internal Darktrace database.

### Breach importance

* Activation Function
