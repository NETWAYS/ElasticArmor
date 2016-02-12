# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+


class classproperty(object):
    """Dead-simple @classproperty decorator

    Usage:
        class Foo(object):
            @classproperty
            def bar(cls):
                return cls

        assert Foo.bar is Foo
        assert Foo().bar is Foo

    Original solution by Denis Ryzhkov @ http://stackoverflow.com/a/13624858."""

    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner):
        return self.func(owner)
