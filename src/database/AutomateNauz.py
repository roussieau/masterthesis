#!/usr/local/bin/python3
import pyautogui
import os
from time import sleep
import clipboard
import sys

f = open("Nauzresult.txt","w+")
pyautogui.PAUSE = 0.5
os.system(r"start C:\Users\jrmen\Downloads\nfd_win32_portable\nfd")
for i in range(5):
    screenWidth, screenHeight = pyautogui.size()
    pyautogui.moveTo(screenWidth / 2, screenHeight / 2)
    pyautogui.moveTo(988,305)
    pyautogui.click(button='left')
    pyautogui.moveTo(758,397)
    pyautogui.click(button='left')
    for j in range(i):
        pyautogui.press('down')
    pyautogui.moveTo(829,674)
    pyautogui.click(button='left')
    pyautogui.hotkey('ctrl','c')
    nameOfFile = clipboard.paste()
    pyautogui.press('enter')
    positionPacked = pyautogui.locateOnScreen(r"C:\Users\jrmen\Pictures\nauz_packer.png")
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
    
    

    

 
