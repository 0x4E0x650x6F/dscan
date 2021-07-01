from setuptools import find_packages, setup

with open('README.md', encoding='utf-8') as f:
    readme_text = f.read()

name = 'dscan-4E656F'
version = '0.1.5'
release = '0.1.5'

setup(
    name=name,
    version=version,
    description=(
        'Wrapper around nmap allow nmap scans to be distributed',
        'With resume, and address optimization.'
    ),
    long_description=readme_text,
    long_description_content_type='text/markdown',
    license="GPL version 3",
    author='0x4E0x650x6F',
    author_email='tiago.alexand@gmail.com',
    url='https://github.com/0x4E0x650x6F/dscan',
    tests_requires=[
        "autopep8", "flake8", "isort", "sphinx",
    ],
    install_requires=[
        'python-libnmap'
    ],
    scripts=['bin/dscan'],
    package_data={
          name: ['data/agent.conf', 'data/dscan.conf'],
       },
    packages=find_packages(include=['dscan', 'dscan.*'], exclude='tests'),
    include_package_data=True,
    python_requires='>=3.6',
    classifiers=[
            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
            "Development Status :: 5 - Production/Stable",
            "Environment :: Console",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Topic :: System :: Networking",
        ],
)
