from setuptools import find_packages, setup
from sphinx.setup_command import BuildDoc

with open('README.md') as f:
    readme = f.read()

cmd_class = {'build_sphinx': BuildDoc}

name = 'dscan'
version = '0.1.0'
release = '0.1.0'

setup(
    name=name,
    version=version,
    description='',
    long_description=readme,
    author='0x4E0x650x6F',
    author_email='tiago.alexand@gmail.com',
    url='www.tiagoalexandre.com',
    test_requires=[
        "autopep8", "flake8", "isort", "sphinx",
    ],
    install_requires=[
        'python-libnmap'
    ],
    scripts=['bin/dscan'],
    cmdclass=cmd_class,
    command_options={
        'build_sphinx': {
            'project': ('setup.py', name),
            'version': ('setup.py', version),
            'release': ('setup.py', release),
            'source_dir': ('setup.py', 'doc')}
    },
    packages=find_packages(exclude='tests')
)
