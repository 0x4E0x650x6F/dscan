from setuptools import find_packages, setup

with open('README.md') as f:
    readme = f.read()

setup(
    name='dscan',
    version='0.1.0',
    description='',
    long_description=readme,
    author='0x4E0x650x6F',
    author_email='tiago.alexand@gmail.com',
    url='www.tiagoalexandre.com',
    install_requires=[],
    scripts=['bin/dscan'],
    packages=find_packages(exclude=('tests'))
)
