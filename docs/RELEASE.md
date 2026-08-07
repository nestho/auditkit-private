# Release Process

## 1. Run tests

~~~bash
python -m unittest discover -s tests
~~~

## 2. Build package

~~~bash
python -m pip install build
python -m build
~~~

Artifacts will be created in:

~~~text
dist/
~~~

## 3. Test CLI

~~~bash
auditkit --version
auditkit --help
~~~

## 4. Create Git tag

~~~bash
git tag -a v0.3.0 -m "AuditKit v0.3.0"
git push origin main --tags
~~~

## 5. Create GitHub release

Create a release from the tag and attach artifacts from dist/ if desired.

Do not attach:

- private license keys
- customer licenses
- .auditkit state
- keys/private_key.pem
