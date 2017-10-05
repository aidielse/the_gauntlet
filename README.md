# The Gauntlet

This is an organized list of cream-of-the-crop pwning challenges that have come out in ctf's over the past few years.

I went through this [list](https://pastebin.com/uyifxgPu) and tracked down every binary that I could.

## Recommended Training

It is highly recommended that you work your way through the following material (in order) before you tackle the gauntlet.

1. [Modern Binary Exploitation](https://github.com/RPISEC/MBE), [website_link_here](http://security.cs.rpi.edu/courses/binexp-spring2015/)
2. [Malware Analysis](https://github.com/RPISEC/Malware)
3. [HITCON-Training](https://github.com/scwuaptx/HITCON-Training)

## Useful Resources

Here are some resources to help you out as you go through the gauntlet.

1. Linux Heap Exploitation
    * [Sploitfun](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
    * [Shellphish how2heap](https://github.com/shellphish/how2heap)
    * [Heap Exploitation Book](https://heap-exploitation.dhavalkapil.com/)
    * [ptmalloc fanzine](http://tukan.farm/2016/07/26/ptmalloc-fanzine/)
2. Linux Kernel Exploitation
    * [Kernel Exploitation Master List](https://github.com/MrMugiwara/linux-kernel-exploitation)
    * [Android Kernel Security](https://github.com/ukanth/afwall/wiki/Kernel-security)
3. [Stack Clash](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt)

## Challenges

### Difficulty: Gotta Start Somewhere

| CTF                   | Challenge                                                                                                 | Solved?       |
|:----------------------|:----------------------------------------------------------------------------------------------------------|:--------------|
| DEFCON 2016           | [xkcd](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/xkcd)                         | __SOLVED__    |
| TOKYO WESTERNS 2016   | [greeting](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/greeting)                 | __SOLVEDISH__ |
| DEFCON 2015           | [babyecho](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/babyecho)                 | __SOLVEDISH__ |
| DEFCON 2015           | [r0pbaby](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/r0pbaby)                   | __SOLVED__    |
| CSAW 2014             | [greenhornd](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/greenhornd)             | UNSOLVED      |
| CSAW 2013             | [csawdiary](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/csawdiary)               | UNSOLVED      |
| CSAW 2013             | [exploit2](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/exploit2)                 | __SOLVED__    |
| CSAW 2013             | [miteegashun](https://github.com/aidielse/pwning/tree/master/gotta_start_somewhere/miteegashun)           | __SOLVED__    |
| PlaidCTF 2013         | [ropasaurusrex](https://github.com/aidielse/the_gauntlet/tree/master/gotta_start_somewhere/ropasaurusrex) | __SOLVED__    | 

### Difficulty: Easy

| CTF                   | Challenge                                                                                                     | Solved?       |
|:----------------------|:--------------------------------------------------------------------------------------------------------------|:--------------|
| BKP 2016              | [complexcalc](https://github.com/aidielse/pwning/tree/master/easy/complexcalc)                                | __SOLVED__    |
| BKP 2016              | [simplecalc](https://github.com/aidielse/pwning/tree/master/easy/simplecalc)                                  | __SOLVED__    |
| CodeGate 2016         | [flOppy](https://github.com/aidielse/pwning/tree/master/easy/fl0ppy)                                          | __SOLVED__    |
| CodeGate 2016         | [serial](https://github.com/aidielse/pwning/tree/master/easy/serial)                                          | __SOLVED__    |
| DEFCON 2016           | [banker](https://github.com/aidielse/pwning/tree/master/easy/banker)                                          | UNSOLVED      |
| DEFCON 2016           | [feedme](https://github.com/aidielse/pwning/tree/master/easy/feedme)                                          | UNSOLVED      |
| DEFCON 2016           | [heapfun4u](https://github.com/aidielse/pwning/tree/master/easy/heapfun4u)                                    | UNSOLVED      |
| DEFCON 2016           | [pillpusher](https://github.com/aidielse/pwning/tree/master/average/pillpusher)                               | __SOLVED__    |
| TOKYO WESTERNS 2016   | [interpreter](https://github.com/aidielse/pwning/tree/master/easy/interpreter)                                | UNSOLVED      |
| 32C3 2015             | [readme](https://github.com/aidielse/pwning/tree/master/easy/readme)                                          | UNSOLVED      |
| DEFCON 2015           | [wibbly\_wobbly\_timey\_wimey](https://github.com/aidielse/pwning/tree/master/easy/wibbly_wobbly_timey_wimey) | UNSOLVED      |
| 31C3 2014             | [cfy](https://github.com/aidielse/pwning/tree/master/easy/cfy)                                                | UNSOLVED      |
| CodeGate 2014         | [angry\_doraemon](https://github.com/aidielse/pwning/tree/master/easy/angry_doraemon)                         | UNSOLVED      |
| DEFCON 2014           | [babysfirstheap](https://github.com/aidielse/pwning/tree/master/easy/babysfirstheap)                          | __SOLVED__    |
| PlaidCTF 2014         | [ezhp](https://github.com/aidielse/pwning/tree/master/easy/ezhp)                                              | UNSOLVED      |
| PlaidCTF 2014         | [sass](https://github.com/aidielse/pwning/tree/master/easy/sass)                                              | UNSOLVED      |
 
### Difficulty: Average

| CTF                   | Challenge                                                                                 | Solved?       |
|:----------------------|-------------------------------------------------------------------------------------------|:--------------|
| CSAW 2017             | [zone](https://github.com/aidielse/the_gauntlet/tree/master/gotta_start_somewhere/zone)   | __SOLVED__    |
| DEFCON 2016           | [crunchtime](https://github.com/aidielse/pwning/tree/master/average/crunchtime)           | UNSOLVED      |
| HITCON 2016           | [babyheap](https://github.com/aidielse/pwning/tree/master/average/babyheap)               | __SOLVED__    |
| HITCON  2016          | [shellingfolder](https://github.com/aidielse/pwning/tree/master/easy/shellingfolder)      | UNSOLVED      |
| TOKYO WESTERNS 2016   | [diary](https://github.com/aidielse/pwning/tree/master/average/diary)                     | UNSOLVED      |
| TOKYO WESTERNS 2016   | [shadow](https://github.com/aidielse/pwning/tree/master/average/shadow)                   | UNSOLVED      |
| BKP 2015              | [jfk-umass](https://github.com/aidielse/pwning/tree/master/average/jfk-umass)             | UNSOLVED      |
| CodeGate 2015         | [bookstore](https://github.com/aidielse/the_gauntlet/tree/master/average/bookstore)       | __SOLVED__    |
| MMA 2015              | [spell](https://github.com/aidielse/pwning/tree/master/average/spell)                     | UNSOLVED      |
| 31C3 2014             | [mynx](https://github.com/aidielse/pwning/tree/master/average/mynx)                       | UNSOLVED      |
| 31C3 2014             | [maze](https://github.com/aidielse/pwning/tree/master/average/maze)                       | UNSOLVED      |
| GITS 2014             | [fuzzy](https://github.com/aidielse/pwning/tree/master/average/fuzzy)                     | UNSOLVED      |
| GITS 2014             | [ti-1337](https://github.com/aidielse/pwning/tree/master/average/ti-1337)                 | UNSOLVED      |
| hack.lu 2014          | [holy-moses](https://github.com/aidielse/pwning/tree/master/average/holy-moses)           | UNSOLVED      |
| hack.lu 2014          | [the-union](https://github.com/aidielse/pwning/tree/master/average/the-union)             | UNSOLVED      |
| PlaidCTF 2014         | [kappa](https://github.com/aidielse/pwning/tree/master/average/kappa)                     | UNSOLVED      |
| pwnable.kr            | unexploitable                                                                             | __SOLVED__    |

### Difficulty: Respectable

| CTF           | Challenge                                                                                 | Solved?       |
|:--------------|:------------------------------------------------------------------------------------------|:--------------|
| BCTF 2016     | [bcloud](https://github.com/aidielse/the_gauntlet/tree/master/respectable/bcloud)         | __SOLVED__    |
| BKP 2016      | [cookbook](https://github.com/aidielse/pwning/tree/master/respectable/cookbook)           | __SOLVED__    |
| BKP 2016      | [segsh](https://github.com/aidielse/pwning/tree/master/respectable/segsh)                 | UNSOLVED      |
| HITCON 2016   | [secretholder](https://github.com/aidielse/pwning/tree/master/respectable/secretholder)   | __SOLVED__    |
| HITCON 2016   | [sleepyholder](https://github.com/aidielse/pwning/tree/master/respectable/sleepyholder)   | UNSOLVED      |
| 32C3 2015     | [ranger](https://github.com/aidielse/pwning/tree/master/respectable/ranger)               | UNSOLVED      |
| CodeGate 2015 | [beef\_steak](https://github.com/aidielse/pwning/tree/master/respectable/beef_steak)      | UNSOLVED      |
| CodeGate 2015 | [sokoban](https://github.com/aidielse/pwning/tree/master/respectable/sokoban)             | UNSOLVED      |
| DEFCON 2015   | [fuckup](https://github.com/aidielse/pwning/tree/master/respectable/fuckup)               | UNSOLVED      |
| DEFCON 2015   | [heapsoffun](https://github.com/aidielse/pwning/tree/master/respectable/heapsoffun)       | UNSOLVED      |
| DEFCON 2015   | [int3rupted](https://github.com/aidielse/pwning/tree/master/respectable/int3rupted)       | UNSOLVED      |
| GITS CTF 2015 | [citadel](https://github.com/aidielse/pwning/tree/master/respectable/citadel)             | UNSOLVED      |
| HITCON 2015   | [readable](https://github.com/aidielse/pwning/tree/master/respectable/readable)           | UNSOLVED      |
| MMA 2015      | [d3flate](https://github.com/aidielse/pwning/tree/master/respectable/d3flate)             | UNSOLVED      |
| 31C3 CTF 2014 | [sarge](https://github.com/aidielse/pwning/tree/master/respectable/sarge)                 | UNSOLVED      |
| 31C3 CTF 2014 | [pong](https://github.com/aidielse/pwning/tree/master/respectable/pong)                   | UNSOLVED      |
| BKP CTF 2014  | [snapstagram](https://github.com/aidielse/pwning/tree/master/respectable/snapstagram)     | UNSOLVED      |
| CodeGate 2014 | [4stone](https://github.com/aidielse/pwning/tree/master/respectable/4stone)               | UNSOLVED      |
| PlaidCTF 2014 | [harry\_potter](https://github.com/aidielse/pwning/tree/master/respectable/harry_potter)  | UNSOLVED      |
| PlaidCTF 2014 | [jackshit](https://github.com/aidielse/pwning/tree/master/respectable/jackshit)           | UNSOLVED      |
| pwnable.kr    | dos4fun                                                                                   | __SOLVED__    |
| pwnable.kr    | tiny                                                                                      | __SOLVED__    |

### Difficulty: Stressful

| CTF           | Challenge                                                                                                         | Solved?       |
|:--------------|:------------------------------------------------------------------------------------------------------------------|:--------------|
| BKP 2016      | [spacerex](https://github.com/aidielse/pwning/tree/master/stressful/spacerex)                                     | UNSOLVED      |
| DEFCON 2016   | [glados](https://github.com/aidielse/pwning/tree/master/stressful/glados)                                         | UNSOLVED      |
| HITCON 2016   | [heartattack](https://github.com/aidielse/pwning/tree/master/stressful/heartattack)                               | UNSOLVED      |
| 32C3 2015     | [bingo](https://github.com/aidielse/pwning/tree/master/stressful/bingo)                                           | UNSOLVED      |
| 32C3 2015     | [sandbox](https://github.com/aidielse/pwning/tree/master/stressful/sandbox)                                       | UNSOLVED      |
| CodeGate 2015 | [olive-and-mushroom-pizza](https://github.com/aidielse/pwning/tree/master/stressful/olive-and-mushroom-pizza)     | UNSOLVED      |
| CodeGate 2015 | [rodent](https://github.com/aidielse/pwning/tree/master/stressful/rodent)                                         | UNSOLVED      |
| DEFCON 2015   | [hackercalc](https://github.com/aidielse/pwning/tree/master/stressful/hackercalc)                                 | UNSOLVED      |
| DEFCON 2015   | [tensixtyseven](https://github.com/aidielse/pwning/tree/master/stressful/tensixtyseven)                           | UNSOLVED      |
| DEFCON 2015   | [thing2](https://github.com/aidielse/pwning/tree/master/stressful/thing2)                                         | UNSOLVED      |
| GITS 2015     | [boxxy](https://github.com/aidielse/pwning/tree/master/stressful/boxxy)                                           | UNSOLVED      |
| HITCON 2015   | [blinkroot](https://github.com/aidielse/pwning/tree/master/stressful/blinkroot)                                   | UNSOLVED      |
| 31C3 2014     | [booking](https://github.com/aidielse/pwning/tree/master/stressful/booking)                                       | UNSOLVED      |
| 31C3 2014     | [nokia-1337](https://github.com/aidielse/pwning/tree/master/stressful/nokia-1337)                                 | UNSOLVED      |
| 9447 2014     | [classy](https://github.com/aidielse/pwning/tree/master/stressful/classy)                                         | UNSOLVED      |
| CodeGate 2014 | [dodosandbox](https://github.com/aidielse/pwning/tree/master/stressful/dodosandbox)                               | UNSOLVED      |
| CodeGate 2014 | [koreanrestaurant](https://github.com/aidielse/pwning/tree/master/stressful/koreanrestaurant)                     | UNSOLVED      |
| CodeGate 2014 | [minibomb](https://github.com/aidielse/pwning/tree/master/stressful/minibomb)                                     | UNSOLVED      |
| DEFCON 2014   | [justify](https://github.com/aidielse/pwning/tree/master/stressful/justify)                                       | UNSOLVED      |
| DEFCON 2014   | [turdedo](https://github.com/aidielse/pwning/tree/master/stressful/turdedo)                                       | UNSOLVED      |
| Olympic 2014  | [zpwn](https://github.com/aidielse/pwning/tree/master/stressful/zpwn)                                             | UNSOLVED      |
| pwnable.kr    | softmmu                                                                                                           | __SOLVED__    |

### Difficulty: Soul Crushing

| CTF           | Challenge                                                                                         | Solved?       |
|:--------------|:--------------------------------------------------------------------------------------------------|:--------------|
| 0CTF 2017     | [knote](https://github.com/aidielse/pwning/tree/master/soul_crushing/knote)                       | UNSOLVED      |
| HITCON 2016   | [house\_of\_orange](https://github.com/aidielse/pwning/tree/master/soul_crushing/house_of_orange) | UNSOLVED      |
| PlaidCTF 2016 | [awkward](https://github.com/aidielse/pwning/tree/master/soul_crushing/awkward)                   | UNSOLVED      |
| CodeGate 2015 | [weff](https://github.com/aidielse/pwning/tree/master/soul_crushing/weff)                         | UNSOLVED      |
| GITS 2015     | [gitschat](https://github.com/aidielse/pwning/tree/master/soul_crushing/gitschat)                 | UNSOLVED      |
| HITCON 2015   | [deathweed](https://github.com/aidielse/pwning/tree/master/soul_crushing/deathweed)               | UNSOLVED      |
| PlaidCTF 2015 | [plaiddb](https://github.com/aidielse/pwning/tree/master/soul_crushing/plaiddb)                   | UNSOLVED      |
| PlaidCTF 2015 | [tp](https://github.com/aidielse/pwning/tree/master/soul_crushing/tp)                             | UNSOLVED      |
| 31C3 2014     | [cfy2](https://github.com/aidielse/pwning/tree/master/soul_crushing/cfy2)                         | UNSOLVED      |
| 31C3 2014     | [saas](https://github.com/aidielse/pwning/tree/master/soul_crushing/saas)                         | UNSOLVED      |
| CodeGate 2014 | [membership](https://github.com/aidielse/pwning/tree/master/soul_crushing/membership)             | UNSOLVED      |
| DEFCON 2014   | [dosfun4u](https://github.com/aidielse/pwning/tree/master/soul_crushing/dosfun4u)                 | UNSOLVED      |
| GITS 2014     | [byte\_sexual](https://github.com/aidielse/pwning/tree/master/soul_crushing/byte_sexual)          | UNSOLVED      |
| hack.lu 2014  | [breakout](https://github.com/aidielse/pwning/tree/master/soul_crushing/breakout)                 | UNSOLVED      |
| hack.lu 2014  | [mario](https://github.com/aidielse/pwning/tree/master/soul_crushing/mario)                       | UNSOLVED      |
| hack.lu 2014  | [oreo](https://github.com/aidielse/pwning/tree/master/soul_crushing/oreo)                         | UNSOLVED      |
| HITCON 2014   | [stkof](https://github.com/aidielse/pwning/tree/master/soul_crushing/stkof)                       | UNSOLVED      |
| pwnable.kr    | towelroot                                                                                         | __SOLVED__    |
