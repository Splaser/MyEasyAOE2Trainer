# MyEasyAOE2Trainer

A small AoE2: Definitive Edition trainer for the current Steam build.

This project was updated manually from an older Cheat Engine table by re-analyzing the current game binary with IDA Pro and rebuilding the resource access logic in Python with `pymem`.

## Features

- Set Food
- Set Wood
- Set Stone
- Set Gold
- Set all resources at once
- Set population limit
- Automatically resolves the local player in single-player/skirmish
- One-shot process access: open → read/write → close

## Usage

```powershell
py aoe2de_resources.py --food 5000
py aoe2de_resources.py --wood 5000
py aoe2de_resources.py --stone 5000
py aoe2de_resources.py --gold 5000
py aoe2de_resources.py --all 5000
py aoe2de_resources.py --population 150
