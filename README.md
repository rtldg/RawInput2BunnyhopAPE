## RawInput2BunnyhopAPE

An external software that ports [momentum mod's](https://momentum-mod.org/) ``m_rawinput 2`` behaviour. This option provides mouse interpolation which will ["line up with the tickrate properly without needing to have a specific framerate"](https://discord.com/channels/235111289435717633/356398721790902274/997026787995435088) (rio). The code for this isn't public and was reverse engineered from the game.


### Because juggling exe's & CS:S launch options is annoying:

Includes **BunnyhopAPE** from [alkatrazbhop](https://github.com/alkatrazbhop/BunnyhopAPE) -> [yupi2](https://github.com/yupi2/BunnyhopAPE) -> [rtldg](https://github.com/rtldg/BunnyhopAPE)
- autohop prediction
- auto-starting CS:S with `-insecure`
	- Now with auto-detecting the steam library path!
- fullscreen hook thing
- (NEW!) viewpunch remover (e.g. from fall-damage)

### Usage
* Run the application.
* Make sure to set ``m_rawinput 2`` in game for it to take effect.
* `F5` to toggle autohop prediction
* `F6` to toggle the fullscreen hook thing which keeps the game open in fullscreen when you alt-tab (which is nice if you have two monitors)
* `F7` to toggle the viewpunch remover. Basically a client-side [SuppressViewpunch](https://github.com/xen-000/SuppressViewpunch)

### Building requirements
* [Microsoft Detours](https://github.com/microsoft/Detours)
