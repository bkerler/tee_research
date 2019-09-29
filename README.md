# tee_research
Some useful ida and ghidra plugins for tee research

## Installation
- For ghidra, do the following:

  Compile loader via
  ```
  gradle -PGHIDRA_INSTALL_DIR=<path_to_your_ghidra_install>	
  ```
  then in Ghidra, select "Install Extensions", press + button and select the zip in the dist folder

Copy the python script to your ~/ghidra_scripts folder

- For ida, do the following:
  Copy the python loader to the loader directory, then run the python script in ida once autoanalyis has finished.

## Trustonic
### Usage
- Use the mclf loader plugin, then run the scripts to get tlApi and other functions labeled

## References

https://github.com/NeatMonster/mclf-ghidra-loader

https://github.com/ghassani/mclf-ida-loader
