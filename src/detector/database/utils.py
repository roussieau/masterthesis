#!/usr/local/bin/python3

def sanitize(dirty_list):
        clean_tab = []
        for i in dirty_list:
            clean_tab.append(i[0])
        return clean_tab