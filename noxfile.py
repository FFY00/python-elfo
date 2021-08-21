# SPDX-License-Identifier: MIT

import nox


nox.options.sessions = ['mypy', 'test']
nox.options.reuse_existing_virtualenvs = True


@nox.session(python='3.7')
def mypy(session):
    session.install('.', 'mypy')

    session.run('mypy', '-p', 'elfo')
