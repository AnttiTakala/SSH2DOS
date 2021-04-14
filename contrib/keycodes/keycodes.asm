; keycode.asm
;
; Utility to print the keyboard code of a pressed key
;
; Compilation:  nasm -f bin -o keycodes.com keycodes.asm
;
;
; This program is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; as published by the Free Software Foundation; either version 2
; of the License, or (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU Library General Public
; License along with this program; if not, write to the Free Software
; Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

                BITS 16
                ORG 0x100
RUN:
                MOV     DX,MSG_1	; print message
                MOV     AH,09H
                INT     21H
LAB1:
                MOV     AH,10H		; wait for a keystroke
                INT     16H

                PUSH    AX
                MOV     DX,AX		; convert it to human-readable
                MOV     CX,4
                MOV     BX,CX
LAB2:
                MOV     AX,DX
                AND     AL,0FH
                CMP     AL,10
                JB      LAB3
                ADD     AL,7
LAB3:
                ADD     AL,30H
                MOV     [MSG_2_KEY+BX-1],AL
                SHR     DX,CL
                DEC     BX
                JNZ     LAB2

                MOV     DX,MSG_2	; print it
                MOV     AH,09H
                INT     21H
                POP     AX

                CMP     AX,011BH	; jump back if not ESC
                JNZ     LAB1

EXIT:
                MOV     AX,4C00H	; quit
                INT     21H


MSG_1           DB      "KeyCodes test <ESC> = 0x011B - exit.", 0Dh, 0AH, "$"
MSG_2           DB      "keycode = 0x"
MSG_2_KEY       DB      "0000", 0DH, 0AH, "$"
