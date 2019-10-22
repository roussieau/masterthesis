#!/usr/local/bin/python3
import pyautogui
import os
from time import sleep
import clipboard
import sys

f = open("Volkolakresult.txt","w+")
pyautogui.PAUSE = 0.5
os.system(r"start C:\Users\jrmen\Downloads\xvlk_win32_public_0.22\xvlk_win32_public\xvlk")
for i in range(5):
    screenWidth, screenHeight = pyautogui.size()
    pyautogui.moveTo(screenWidth / 2, screenHeight / 2)
    pyautogui.moveTo(1014,246)
    pyautogui.click(button='left')
    pyautogui.moveTo(659,367)
    pyautogui.click(button='left')
    for j in range(i):
        pyautogui.press('down')
    pyautogui.moveTo(726,642)
    pyautogui.click(button='left')
    pyautogui.hotkey('ctrl','c')
    nameOfFile = clipboard.paste()
    pyautogui.press('enter')
    positionPacked = pyautogui.locateOnScreen(r"C:\Users\jrmen\Pictures\xvolk_packer.png")
    if positionPacked != None :
        pyautogui.moveTo(positionPacked)
        pyautogui.moveRel(100, None)
        pyautogui.click(button='left')
        pyautogui.hotkey('ctrl','c')
        packer = clipboard.paste()
        f.write(nameOfFile + ' - YES - ' + packer + ' - \n')
    else :
        f.write(nameOfFile + ' - NO - NULL - \n')
f.close()
    

    

 
