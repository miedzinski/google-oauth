# -*- coding: utf-8 -*-

from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(
    name='google-oauth',
    version='1.0.1',
    packages=['google_oauth'],
    description='OAuth2 for Google APIs',
    long_description=readme(),
    url='https://github.com/miedzinski/google-oauth',
    author='Dominik Miedziński',
    license='MIT License',
    classifiers=(
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Internet',
    ),
    keywords='google oauth oauth2 api service jwt',
    install_requires=[
        'pyopenssl>=0.11',
        'requests',
        'six',
    ],
    test_suite='tests',
)
