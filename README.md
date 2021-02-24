# PyDNS

PyDNS is a simple DNS Server written in Python. It follows the conventions and protocol documented on https://www.ietf.org/rfc/rfc1035.txt , however it currently only supports UDP and does not support DNS Recursion.

## How can I use it?

Simple! We have a docker image already setup, if you would like to use PyDNS simply clone this repository, change your zone settings in `zones.json`, and run the following command from your terminal. ( It hasn't been tested on Windows yet )
```
docker-compose up -d
```

## I would like to contribute

Thats great! We 100% encourage you to. Please look at the [issues](https://github.com/CatDevz/PyDNS/issues) before contributing, if you have a feature you would like to add that is not already on there please add it first, with a note that you will work on it. Once your done with your changes submit a pull request.

### Contributers

- [Cody Q](https://github.com/CatDevz/)

### License

PyDNS is licensed under GNU General Public License v3.0

[Full License](https://github.com/CatDevz/PyDNS/blob/master/LICENSE)
