#!/usr/local/bin/python3
import pyautogui
import os
from time import sleep
import clipboard
import sys

f = open("EXEInforesult.txt","w+")
pyautogui.PAUSE = 0.5
os.system(r"start C:\Users\jrmen\Downloads\exeinfo-pe-0-0-5-1\ExeinfoPe\exeinfope")
for i in range(5):
    screenWidth, screenHeight = pyautogui.size()
    pyautogui.moveTo(screenWidth / 2, screenHeight / 2)
    pyautogui.moveTo(943,368)
    pyautogui.click(button='left')
    pyautogui.moveTo(868,555)
    pyautogui.click(button='left')
    pyautogui.moveTo(846,583)
    pyautogui.click(button='left')
    pyautogui.moveTo(613,255)
    pyautogui.click(button='left')
    for j in range(i):
        pyautogui.press('down')
    pyautogui.moveTo(780,530)
    pyautogui.click(button='left')
    pyautogui.hotkey('ctrl','c')
    nameOfFile = clipboard.paste()
    pyautogui.press('enter')
    pyautogui.moveTo(674,526)
    pyautogui.click(button='left')
    pyautogui.hotkey('control','a')
    pyautogui.hotkey('control','c')
    result = clipboard.paste()
    pyautogui.moveTo(674,556)
    pyautogui.click(button='left')
    pyautogui.hotkey('control','a')
    pyautogui.hotkey('control','c')
    unpackInfo = clipboard.paste()
    if("Not packed" or "try other" in unpackInfo) or ("Nothing" or "Unknown" in result) :
        f.write(nameOfFile + ' - NO - NULL - \n')
    else :
        f.write(nameOfFile + ' - YES - ' + unpackInfo + ' - \n')
f.close()
