#!/usr/local/bin/python3
import pyautogui
import os
from time import sleep
import clipboard
import sys

f = open("PEiDresult.txt","w+")
pyautogui.PAUSE = 0.3
os.system(r"start C:\Users\jrmen\Desktop\PEiD")
for i in range(5):
    screenWidth, screenHeight = pyautogui.size()
    pyautogui.moveTo(screenWidth / 2, screenHeight / 2)
    pyautogui.moveTo(906,355)
    pyautogui.click(button='left')
    pyautogui.moveTo(1111,753)
    pyautogui.click(button='left')
    pyautogui.moveTo(1100,784)
    pyautogui.click(button='left')
    pyautogui.moveTo(874,478)
    pyautogui.click(button='left')
    for j in range(i):
        pyautogui.press('down')
    pyautogui.moveTo(908,751)
    pyautogui.click(button='left')
    pyautogui.hotkey('ctrl','c')
    nameOfFile = clipboard.paste()
    pyautogui.press('enter')
    pyautogui.moveTo(900,490)
    pyautogui.mouseDown()
    pyautogui.moveTo(520,490)
    pyautogui.mouseUp()
    pyautogui.hotkey('ctrl','c')
    result = clipboard.paste()
    if "Nothing" in result :
        f.write(nameOfFile + ' - NO - NULL - \n')
    else :
        f.write(nameOfFile + ' - YES - ' + result + ' - \n')
f.close()

    
