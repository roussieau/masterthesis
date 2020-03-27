def convert_f9(series):
    return series.apply(lambda x: 0 if x == 0 else 1)

def convert_f10(series):
    return series.apply(lambda x: 1 if x == 4_194_304 else 0)

def convert_f11(series):
    def convert(x):
        if x == 4096:
            return 1
        elif x == 8192:
            return 2
        return 0
    return series.apply(convert)

def convert_f12(series):
    def convert(x):
        if x == 4:
            return 1
        elif x == 5:
            return 2
        return 0
    return series.apply(convert)

def convert_f13(series):
    return series.apply(lambda x: 1 if x == 0 else 0)

def convert_f14(series):
    return series.apply(lambda x: 1 if x < 250000 else 0)

def convert_f15(series):
    return series.apply(lambda x: 1 if x < 50000 else 0)

def convert_f16(series):
    def convert(x):
        if x == 1024:
            return 1
        elif x == 4096:
            return 2
        elif x == 512:
            return 3
        elif x == 1536:
            return 4
        return 0
    return series.apply(convert)


def convert_f18(series):
    return series.apply(lambda x: 1 if x == 0 else 0)


def convert_f19(series):
    return series.apply(lambda x: 1 if x == 1048576 else 0)

def convert_f20(series):
    def convert(x):
        if x == 4096:
            return 1
        elif x == 16384:
            return 2
        elif x == 8192:
            return 3
        elif x == 65536:
            return 4
        return 0
    return series.apply(convert)

def convert_f21(series):
    def convert(x):
        if x == 4096:
            return 1
        elif x == 8192:
            return 2
        return 0
    return series.apply(convert)

def convert_f22(series):
    return series.apply(lambda x: x if x < 9 else 9)

def convert_f23(series):
    return series.apply(lambda x: x if x < 4 else 4)

def convert_f24(series):
    return series.apply(lambda x: 1 if x == 1 else 0)

def convert_f25(series):
    return series.apply(lambda x: 1 if x < 3 else 3)

def convert_f26(series):
    return series.apply(lambda x: x if x < 5 else 5)

def convert_f27(series):
    return series.apply(lambda x: x if x < 3 else 3)

def convert_f28(series):
    return series.apply(lambda x: x if x < 3 else 3)

def convert_f29(series):
    return series.apply(lambda x: x if x < 5 else 5)

def convert_f30(series):
    return series.apply(lambda x: x if x < 3 else 3)

def convert_f37(series):
    def convert(x):
        if x > 0:
            return 1
        elif x < 0:
            return -1
        return 0
    return series.apply(convert)

def convert_f38(series):
    return series.apply(lambda x: x if x < 3 else 3)

def convert_f39(series):
    return series.apply(lambda x: x if x < 4 else 4)

def convert_f40(series):
    def convert(x):
        if x > 0:
            return 1
        elif x < 0:
            return -1
        return 0
    return series.apply(convert)

def convert_f41(series):
    return 1 if x == 0 else 0

def convert_f43(series):
    return 1 if x == -1 else 0
