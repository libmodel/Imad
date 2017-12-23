# to.panga for iOS 11 (up to 11.1.2) [a WIP project for devs only]

What it achieves so far:

* tfp0 (thanks to @i4nbeer)
* patched version of bootstrap + Cydia 64-bit
* AMFI codesigning stuff (thanks to @xerub)
* PoC `jailbreakd` daemon to inject a given set of processes

---
### notes:
There are two methods currently used to grab hashes for amfi. xerub's and another method that supports FAT binaries (yes, Cydia is FAT).

When opening Cydia, it'll take 2-3 seconds because it is waiting for `cydo` to be injected by `jailbreakd`. Sources _should_ show up but refreshing will end up with an `http signal 6 error`.. not sure what's killing it yet.

I might just ditch Cydia because of the mess. Cydia is a great tool but it's just too big, complex, and old for what it does.


---

### to-do:

* fix whatever is killing/aborting `http` or even better, not use Cydia at all.
* improve `jailbreakd`

---

### how do I install:

if you're asking this question then it's better for you not to do so. to.panga will partially jailbreak your phone and I am not responsible for any mess up. This project is for research only.

no offsets needed because we don't do any kernel calls ;)

tested on X and 7

oh and please don't complain about the code or bootstrap. Any unnecessary files or code will eventually be removed or improved.

--

by Abraham Masri @cheesecakeufo


thanks to @xerub, @stek29 and @nullriver and _obviously_, @i4nbeer for the exploit <3

---
if you plan to use any of my code, please give credit. thx.
