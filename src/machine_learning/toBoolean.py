import pandas as pd

class BufferDF:
    def __init__(self):
        self.df = pd.DataFrame()

    def get_df(self):
        return self.df

    def add(self, feature_name, value):
        if value is None:
            return #Do nothing

        already_boolean = len(value.value_counts()) == 2
        if already_boolean:
            self.df[feature_name] = value
        else:
            dum = pd.get_dummies(value, prefix=feature_name, drop_first=True)
            self.df = pd.concat([self.df, dum], axis=1)


def do_nothing(series):
    return series

def delete(series):
    return None

def check_zero(series):
    return series.apply(lambda x: 1 if x == 0 else 0)

def check_negative(series):
    return series.apply(lambda x: 1 if x == -1 else 0)

def check_ratio(series):
    def convert(x):
        if x > 1:
            return 1
        elif x < 1:
            return 2 
        return 0
    return series.apply(convert)

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
    return series.apply(lambda x: 1 if x < 3 else 0)

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

def convert_f38(series):
    return series.apply(lambda x: x if x < 3 else 3)

def convert_f39(series):
    return series.apply(lambda x: x if x < 4 else 4)


functions = [
        None, # To start the list at index 1
        do_nothing, #f1
        do_nothing, #f2
        do_nothing, #f3
        do_nothing, #f4
        do_nothing, #f5
        do_nothing, #f6
        do_nothing, #f7
        do_nothing, #f8
        check_zero, #f9
        convert_f10,
        convert_f11,
        convert_f12,
        check_zero, #f13
        convert_f14,
        convert_f15,
        convert_f16,
        delete, # f17
        check_zero, # f18
        convert_f19,
        convert_f20,
        convert_f21,
        convert_f22,
        convert_f23,
        convert_f24,
        convert_f25,
        convert_f26,
        convert_f27,
        convert_f28,
        convert_f29,
        convert_f30,
        do_nothing, #f31
        do_nothing, #f32
        do_nothing, #f33
        do_nothing, #f34
        do_nothing, #f35
        do_nothing, #f36
        check_ratio, #f37
        convert_f38,
        convert_f39,
        check_ratio, #f40
        check_zero, #f41
        do_nothing, #f42
        check_negative, #43
        check_negative,#f44
        check_negative,#f45
]

def convert(df,all_features):
    buff = BufferDF()
    for i in range(1,46):
        feature = 'f{}'.format(i)
        #print("for {} we use {}".format(feature, functions[i]))
        buff.add(feature, functions[i](df[feature]))

    if all_features:
        for i in range(46,118):
            feature = 'f{}'.format(i)
            #print("for {} we use {}".format(feature, check_zero))
            buff.add(feature, check_zero(df[feature]))

    # We delete features 46 to 117
    buff.add('f118', df['f118'])

    if all_features:
        buff.add('f119', check_zero(df['f119']))

    return buff.get_df()
