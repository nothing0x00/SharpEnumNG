# SharpEnumNG

This repository contains an updated version of the SharpEnum C# enumeration script. Unlike the original version, this version operates without any invocations of either Powershell or CMD, with most functionality being implemented in Windows API calls.

The intention behind this approach is to bypass heuristic detections which rely on process calls to specific processes, namely Powershell and CMD.

In testing, the footprint of this version is significantly lighter, with the runtim completing more quickly and the number of spawned processes being muich lower than the original script.

This is a work in progress, so expect updates as time allows.