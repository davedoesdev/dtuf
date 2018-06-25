import os
from setuptools import setup

def read(name):
    return open(os.path.join(os.path.dirname(__file__), name)).read()

setup(
    name='python-dtuf',
    version='3.2.0',
    description="Docker registry bindings for The Update Framework",
    long_description=read('README.rst'),
    keywords='docker registry tuf update framework',
    author='David Halls',
    author_email='dave@davedoesdev.com',
    url='https://github.com/davedoesdev/dtuf',
    license='MIT',
    packages=['dtuf'],
    entry_points={'console_scripts': ['dtuf=dtuf.main:main']},
    install_requires=['tuf>=0.11.1',
                      'python-dxf>=7.3.0',
                      'fasteners>=0.14.1',
                      'tqdm>=4.19.4',
                      'pytimeparse>=1.1.7',
                      'decorator>=4.1.2',
                      'iso8601>=0.1.12',
                      'securesystemslib>=0.10.8',
                      'colorama>=0.3.9']
)
