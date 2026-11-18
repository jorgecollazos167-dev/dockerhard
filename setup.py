from setuptools import setup, find_packages

setup(
    name='docker-hardener',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'click',
        'rich',
        'docker'
    ],
    entry_points={
        'console_scripts': [
            'dockerhard=hardener.cli:cli'
        ],
    },
    author='Jorge Collazos',
    description='CLI para análisis y hardening de imágenes Docker en entornos de videojuegos Linux',
)