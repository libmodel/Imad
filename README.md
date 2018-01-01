# to.panga for iOS 11 (up to 11.1.2) [a WIP project for devs only]

## Note: I will not be providing updates anymore since many other projects already achieve the same goal. Au revoir!

_to.panga: where the mountain (kernel) meets the sea (user)_

What it achieves so far:

* tfp0 (thanks to @i4nbeer)
* patched version of bootstrap
* AMFI codesigning stuff (thanks to @xerub)
* PoC `jailbreakd` daemon to inject a given set of processes
* able to install few packages from multiple sources (dpkg is 70-80% fixed)

---
### notes:
There are two methods currently used to grab hashes for amfi. xerub's and another method that supports FAT binaries.

When opening Cydia, it'll take 2-3 seconds because it is waiting for `cydo` to be injected by `jailbreakd`. Sources _should_ show up but refreshing will end up with an `http signal 6 error`.. not sure what's killing it yet.

Cydia is probably not going to work with to.panga due to the structure. If you are interested in using Cydia, please wait for a full jailbreak (probably @Morpheus______ should do the job).

this tool is really meant for developers only.

---

### to-do:

* fix dpkg's lzma support
* fix dependencies issues with dpkg (currently uses --force-all)
* improve `jailbreakd` to avoid panics

---

### how do I install:

if you're asking this question then it's better for you not to do so. to.panga will partially jailbreak your phone and I am not responsible for any mess up. This project is for research only.

no offsets needed because we don't do any kernel calls ;)

tested on X and 7

oh and please don't complain about the code or bootstrap. Any unnecessary files or code will eventually be removed or improved.

--

by Abraham Masri @cheesecakeufo

thanks to @coolstarorg and @Morpheus______ for the updated bootstrap binaries and libs.

thanks to @xerub, @stek29 and @nullriver and _obviously_, @i4nbeer for the exploit <3

---
if you plan to use any of my code, please give credit. thx.

