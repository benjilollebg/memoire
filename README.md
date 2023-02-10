# Master Thesis : Application Specific network Queue (ASQ)

todo : Simple overview of use/purpose.

## Description

todo : An in-depth paragraph about your project and overview of use.

## Getting Started

### Dependencies

todo : 	* Describe any prerequisites, libraries, OS version, etc., needed before installing program.
	* ex. Windows 10

### Installing

todo :  How/where to download your program
todo :  Any modifications needed to be made to files/folders

### Executing program

Two folders are located at the root of the project : HOST & NIC. As suspected they contain the code to run on the host and on the nic. 
The same folders name are located inside, when runing a program, you have to run the program located on the same subfolder for it to run

ex : To run the code where the Host share a piece of memory in DMA with the Nic you have to run HOST/dma/host_memory/dma.c on the Host 
and NIC/dma/host_memory/dma.c on the Nic (the name of the c program may not be the same in the 2 subfolders).

#### To run a .c file

* go to the desired folder

```
meson build
ninja -C build
./build/EXECUTABLE
```

## Help

Any advise for common problems or issues.
```
command to run if program contains helper info
```

## Authors

Contributors names and contact info

ex. Dominique Pizzie  
ex. [@DomPizzie](https://twitter.com/dompizzie)

## Version History

* 0.2
    * Various bug fixes and optimizations
    * See [commit change]() or See [release history]()
* 0.1
    * Initial Release

## License

This project is licensed under the [NAME HERE] License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [awesome-readme](https://github.com/matiassingers/awesome-readme)
* [PurpleBooth](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)
* [dbader](https://github.com/dbader/readme-template)
* [zenorocha](https://gist.github.com/zenorocha/4526327)
* [fvcproductions](https://gist.github.com/fvcproductions/1bfc2d4aecb01a834b46)
