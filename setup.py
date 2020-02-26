import os
from setuptools import setup

def read(name):
    return open(os.path.join(os.path.dirname(__file__), name)).read()

setup(
    name='python-dtuf',
    version='4.0.0',
    description="Docker registry bindings for The Update Framework",
    long_description=read('README.rst'),
    keywords='docker registry tuf update framework',
    author='David Halls',
    author_email='dave@davedoesdev.com',
    url='https://github.com/davedoesdev/dtuf',
    license='MIT',
    packages=['dtuf'],
    entry_points={'console_scripts': ['dtuf=dtuf.main:main']},
    install_requires=['tuf>=0.12.2',
                      'python-dxf>=7.6.0',
                      'fasteners>=0.15',
                      'tqdm>=4.43.0',
                      'pytimeparse>=1.1.8',
                      'decorator>=4.4.1',
                      'iso8601>=0.1.12',
                      'securesystemslib>=0.14.1',
                      'colorama>=0.4.3']
)
