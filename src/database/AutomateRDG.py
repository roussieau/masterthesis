
#!/usr/local/bin/python3
import pyautogui
import os
from time import sleep
import clipboard
import sys

f = open("RDGresult.txt","w+")
pyautogui.PAUSE = 0.5
os.system(r"start C:\Users\jrmen\Downloads\RDG\RDG\RDG")
pyautogui.press('enter')
for i in range(5):
    screenWidth, screenHeight = pyautogui.size()
    pyautogui.moveTo(screenWidth / 2, screenHeight / 2)
    pyautogui.moveTo(890,400)
    pyautogui.click(button='left')
    pyautogui.moveTo(906,355)
    pyautogui.click(button='left')
    pyautogui.moveTo(1060,753)
    pyautogui.click(button='left')
    pyautogui.moveTo(1050,790)
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
    pyautogui.moveTo(761,543)
    pyautogui.click(button='left')
    pyautogui.moveTo(899,531)
    pyautogui.click(button='left')
    sleep(10)
    imgPosition = pyautogui.locateOnScreen(r"C:\Users\jrmen\Downloads\RDG\RDG\RDG_nothing.png")
    if imgPosition != None :
        f.write(nameOfFile + ' - NO - NULL - \n')
    else :
        f.write(nameOfFile + ' - YES - NULL - \n')
        pyautogui.moveTo(921,383)
        pyautogui.click(button='left')  
f.close()
    

    
