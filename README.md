## RawInput2BunnyhopAPE

![main ui](https://github.com/rtldg/RawInput2BunnyhopAPE/assets/55846624/78b9702f-cf36-487d-8664-795863b9b3e8)
![map download progress](https://github.com/rtldg/RawInput2BunnyhopAPE/assets/55846624/f9bf901c-0d10-46f1-a3f3-e2941ad06560)
![bytes uncompressed and written](https://github.com/rtldg/RawInput2BunnyhopAPE/assets/55846624/695e509f-9a28-41e5-802a-30fe44784a0f)

An external software that ports [momentum mod's](https://momentum-mod.org/) ``m_rawinput 2`` behaviour. This option provides mouse interpolation which will ["line up with the tickrate properly without needing to have a specific framerate"](https://discord.com/channels/235111289435717633/356398721790902274/997026787995435088) (rio). The code for this isn't public and was reverse engineered from the game.


### Because juggling exe's & CS:S launch options is annoying:

Includes **BunnyhopAPE** from [alkatrazbhop](https://github.com/alkatrazbhop/BunnyhopAPE) -> [yupi2](https://github.com/yupi2/BunnyhopAPE) -> [rtldg](https://github.com/rtldg/BunnyhopAPE)
- autohop prediction
- auto-starting CS:S with `-insecure`
	- Now with auto-detecting the steam library path!
- fullscreen hook thing
- (NEW!) viewpunch remover (e.g. from fall-damage)
- (NEW!) show file (e.g. map) download progress when loading
- (NEW!) use the magic of https://fastdl.me to connect to servers that'd give you "Map differs" or "Missing map" errors on connect https://github.com/rtldg/RawInput2BunnyhopAPE/pull/1

### Usage
* Download the latest RawInput2BunnyhopAPE.exe from the [Releases](https://github.com/rtldg/RawInput2BunnyhopAPE/releases) page.
* Run RawInput2BunnyhopAPE.exe
* Make sure to set ``m_rawinput 2`` in game for it to take effect.
* `F5` to toggle autohop prediction (OFF by default) (you shouldn't need this anymore now that bhoptimer supports sv_autobunnyhopping)
* `F6` to toggle the fullscreen hook thing which keeps the game open in fullscreen when you alt-tab (which is nice if you have two monitors) (off by default)
* `F7` to toggle the viewpunch remover. Basically a client-side [SuppressViewpunch](https://github.com/xen-000/SuppressViewpunch) (on by default)

### How does the fastdl map thing work?
|                                                  | You don't have `mapname` downloaded | You have `mapname` downloaded |
| ------------------------------------------------ | ----------------------------------- | ----------------------------- |
| Server's fastdl has `mapname`:                   | Downloads `mapname` from server's fastdl. If `Map differs` error then you have to reconnect. | |
| Server's fastdl has the wrong map for `mapname`: | Downloads `mapname` from server's fastdl. If `Map differs` error then you have to reconnect. | |
| Server's fastdl does not have `mapname`:         | Downloads the correct map from `fastdl.me` as `mapname`. | **If your map isn't the same map as the server's then it'll download the correct map from `fastdl.me` (and name it `<SHA1>.bsp`).** |

It should be possible to fix `Map differs` errors when you download from the server's fastdl, but it hasn't been worked on yet.

### Cloning & building
- `git clone --recurse-submodules https://github.com/rtldg/RawInput2BunnyhopAPE.git`
- Then just build it with Visual Studio 2022+ haha!
