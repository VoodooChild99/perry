# Perry

Perry is a tool to automatically generate hardware models from corresponding hardware drivers. Please refer to our USENIX Security'24 paper for more details: [*"A Friend's Eye is A Good Mirror: Synthesizing MCU Peripheral Models from Peripheral Drivers"*](https://www.usenix.org/conference/usenixsecurity24/presentation/lei).

## Environment
Perry is tested under the following environment:
* Ubuntu 20.04
* LLVM/Clang 13
* Z3 4.11.0 or above

## Build With Docker
We recommend building Perry with Docker.

Execute the following command to build the image. In case you need a proxy, set the environment variable `PROXY_ADDRESS`:
```shell
# PROXY_ADDRESS=http://xx.xx.xx.xx:xx
./build_docker.sh
```
> This will build a docker image `"perry"` which contains all the necessary materials to execute Perry and reproduce our experiments.

To launch the container:
```shell
./run_docker.sh
```
> A container `"perry"` will be created the first time you execute the script. You should be able to see a shell spawned within the container. The container is still running even if you exit from the shell, which means that you can always spawn a new shell by executing the script later.

All materials are places under the `/root` directory of the container:

| Path | Description |
| :--- | :--- |
| `/root/perry` | Perry source code and binaries |
| `/root/perry-clang-plugin` | [Perry Clang plugin and compiler wrapper source code](https://github.com/VoodooChild99/perry-clang-plugin) and binaries |
| `/root/perry-experiments` | [Artifacts to reproduce Perry's experiments](https://github.com/VoodooChild99/perry-experiments) |
| `/root/HAL-Collection` | [Drivers used in Perry's experiments](https://github.com/VoodooChild99/perry-drivers) |
| `/root/qemu` | QEMU v7.2 source code and binaries, used to emulate firmware |
| `/root/qemu-system-fuzzing` | [Source code of our QEMU fork](https://github.com/VoodooChild99/qemu-system-fuzzing), used to fuzz firmware |
| `/root/AFL` | AFL source code and binaries, used to fuzz firmware |
| `/root/gcc-arm-none-eabi-10.3-2021.10` | GNU Arm embedded toolchain, used to compile drivers |
| `/root/gperftools` and `/root/z3` | Dependencies of Perry/KLEE |

## Use the Pre-Built Docker Image
In case you cannot build a image, we provide a [pre-built docker image on Docker Hub](https://hub.docker.com/r/ray999/perry). Execute the following command to use it:
```shell
docker rmi perry:latest
docker pull ray999/perry
docker tag ray999/perry perry:latest
cd perry
./run_docker.sh
```

## Usage
To synthesize hardware models with Perry, run the following commands:
```shell
python synthesizer/synthesize.py [-c CONFIG-FILE] [-o OUTPUT-DIR] [-a]
```
* `-c CONFIG-FILE`: YAML-format config file for the synthesizer. For an example, please refer to `synthesizer/example/*/config.yaml` (e.g., [`synthesizer/example/STM32F103/config.yaml`](./synthesizer/example/STM32F103/config.yaml)).
* `-o OUTPUT-DIR`: Where to write the generated model. (default to stdout if not specified)
* `-a`: Output everything within a single file so that you can easily integrate the model into QEMU. If not set, models for the board and each peripheral are splitted into multiple files.

## Supporting New MCUs
Currently supported MCUs are listed in [`synthesizer/example`](./synthesizer/example). The following steps are required to support a new MCU:
1. Compile drivers for the MCU with our [Perry Clang plugin and compiler wrapper](https://github.com/VoodooChild99/perry-clang-plugin) to collect auxiliary information and generate LLVM bitcode files. Please refer to the `README` file in the repo for how to use them.
2. Write a configuration file for the MCU. Please refer to `synthesizer/example/*/config.yaml` (e.g., [`synthesizer/example/STM32F103/config.yaml`](./synthesizer/example/STM32F103/config.yaml)) for how to write a configuration file.
3. Execute Perry using the configuration file.

## Replicating Our Experiments
Please refer to the [perry-experiments repository](https://github.com/VoodooChild99/perry-experiments) for more details.

## Citing The Papaer
```
@inproceedings {LEI::SEC24::PERRY,
    title = {A Friend’s Eye is A Good Mirror: Synthesizing MCU Peripheral Models from Peripheral Drivers},
    booktitle = {33rd USENIX Security Symposium (USENIX Security)},
    year = {2024},
    author={Chongqing Lei and Zhen Ling and Yue Zhang and Yan Yang and Junzhou Luo and Xinwen Fu}
}
```