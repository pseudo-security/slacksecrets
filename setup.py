from setuptools import setup, find_packages

setup(
    name='slacksecrets',
    version='0.1.0a1',
    python_requires='>=3.5',
    packages=find_packages(),
    package_data={'slacksecrets': ['rules/*.yar']},
    include_package_data=True,
    url='https://github.com/pseudo-security/slacksecrets',
    license='GPLv3',
    author='pseudo-security',
    author_email='me@pseudo-security.io',
    description='Uncover credentials, API tokens, and other sensitive content in your Slack instance.',
    keywords='slack secrets api credentials tokens',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Topic :: Communications :: Chat',
        'Topic :: Utilities',
        'Programming Language :: Python :: 3',
    ],

    install_requires=[
        'colorama',
        'pony',
        'slackclient',
        'tqdm',
        'yara-python',
    ],

    entry_points={
        'console_scripts': [
            'slacksecrets=slacksecrets.cli:main'
        ]
    }
)
