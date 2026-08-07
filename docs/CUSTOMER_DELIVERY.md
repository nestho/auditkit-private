# Customer Delivery

After payment, deliver the following:

## 1. Package

Example:

~~~text
auditkit-0.3.0-py3-none-any.whl
~~~

## 2. License file

Example:

~~~text
auditkit.lic
~~~

## 3. Public key

Example:

~~~text
auditkit_public.pem
~~~

## 4. Activation instructions

Customer runs:

~~~bash
python3 -m pip install auditkit-0.3.0-py3-none-any.whl
auditkit license activate \
  --license-file auditkit.lic \
  --public-key auditkit_public.pem
auditkit license status
~~~

## 5. Support

Include:

- one installation support message
- authorized-use reminder
- optional upgrade terms
