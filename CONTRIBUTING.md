## Contributing In General
Our project welcomes external contributions. If you have an itch, please feel
free to scratch it.

To contribute code or documentation, please submit a [pull request](https://github.com/IBM/network-config-analyzer/pulls).

A good way to familiarize yourself with the codebase and contribution process is
to look for and tackle low-hanging fruit in the [issue tracker](https://github.com/ibm/network-config-analyzer/issues).

### Proposing new features

If you would like to implement a new feature, please [raise an issue](https://github.com/ibm/network-config-analyzer/issues)
before sending a pull request so the feature can be discussed. This is to avoid
you wasting your valuable time working on a feature that the project developers
are not interested in accepting into the code base.

### Fixing bugs

If you would like to fix a bug, please [raise an issue](https://github.com/ibm/network-config-analyzer/issues) before sending a
pull request, so it can be tracked.

### Merge approval

The project maintainers will review any proposed code in a pull request. A change requires approval from at least one of the
maintainers.

For a list of the maintainers, see the [MAINTAINERS.md](MAINTAINERS.md) page.

## Legal

Each source file must include a license header for the Apache
Software License 2.0. Using the SPDX format is the simplest approach.
e.g.

```
/*
Copyright <holder> All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
```

We have tried to make it as easy as possible to make contributions. This
applies to how we handle the legal aspects of contribution. We use the
same approach - the [Developer's Certificate of Origin 1.1 (DCO)](https://github.com/hyperledger/fabric/blob/master/docs/source/DCO1.1.txt) - that the Linux® Kernel [community](https://elinux.org/Developer_Certificate_Of_Origin)
uses to manage code contributions.

We simply ask that when submitting a patch for review, the developer
must include a sign-off statement in the commit message.

Here is an example Signed-off-by line, which indicates that the
submitter accepts the DCO:

```
Signed-off-by: John Doe <john.doe@example.com>
```

You can include this automatically when you commit a change to your
local git repository using the following command:

```
git commit -s
```

## Communication
Please feel free to email each one of the [maintainers](MAINTAINERS.md).

## Setup
To set up a development environment follow the instructions below.
### Linux
```shell
git clone git@github.com:IBM/network-config-analyzer.git
cd network-config-analyzer
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Windows (using [Git bash](https://git-scm.com/downloads))
```shell
git clone git@github.com:IBM/network-config-analyzer.git
cd network-config-analyzer
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
```

Verify your setup by running `python -m nca -h`. You should get NCA's usage text.

We recommend using either [PyCharm](https://www.jetbrains.com/pycharm/) or [VSCode](https://code.visualstudio.com/) for writing your Python code.

## Testing
Please run both unit testing and end-to-end testing, and make sure they pass before opening a pull request.

Running unit testing from the project root directory:
```shell
PYTHONPATH=$PWD python tests/run_unittests.py
```

Running end-to-end tests from the project root directory:
```shell
PYTHONPATH=$PWD python tests/run_all_tests.py
```

## Coding style guidelines
We use [flake8](https://flake8.pycqa.org/en/latest/) to loosely enforce style.

Install *flake8* to your virtual environment:
```shell
pip install flake8
```

Run *flake8* from the project root directory to check style:
```shell
flake8 nca --max-complexity=15 --max-line-length=127
```
