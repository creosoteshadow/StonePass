// file ui.cpp -- a simple text-based User Interface toolset
#define _CRT_DECLARE_NONSTDC_NAMES 1

#include "windows_fix.h"
#include <conio.h>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <chrono>
#include <thread>
#include "ui.h"

namespace ui {

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    void set_highlight() { SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void set_normal() { SetConsoleTextAttribute(hConsole, 7); }

    void gotoxy(int x, int y) {
        COORD c = { (SHORT)x, (SHORT)y };
        SetConsoleCursorPosition(hConsole, c);
    }
    void cls() { system("cls"); }

    // Helper: is this field focusable?
    bool is_focusable(const InputField& f) {
        return f.type == STRING_INPUT || f.type == INT_INPUT || f.type == BUTTON;
    }

    // Move focus forward / backward, skipping DISPLAY fields
    void move_focus(int direction, FIELDS& fields, int &active) {
        int steps = 0;
        do {
            active += direction;
            if (active < 0) active = (int)fields.size() - 1;
            if (active >= (int)fields.size()) active = 0;
            if (is_focusable(fields[active])) break;
            steps++;
        } while (steps < (int)fields.size()); // safety
    }

    void paint(FIELDS& fields, int active) {
        cls();

        for (size_t i = 0; i < fields.size(); ++i) {
            auto& f = fields[i];

            // keep value_int always in sync
            if (f.type == INT_INPUT) {
                if (f.value_str.empty()) {
                    f.value_int = 0;
                }
                else {
                    try {
                        f.value_int = std::stoi(f.value_str);
                    }
                    catch (...) {
                        // invalid — could highlight red, but for now just keep old
                    }
                }
            }

            gotoxy(f.col, f.row);

            if (f.type == DISPLAY) {
                std::cout << f.prompt;           // just display, no color change
                continue;
            }

            bool focused = is_focusable(f) && (int)i == active;

            if (focused) set_highlight();
            std::cout << f.prompt;
            if (focused) set_normal();

            gotoxy(f.col + (int)f.prompt.length(), f.row);

            if (f.type == BUTTON) {
                if (focused) set_highlight();
                std::cout << "[" << f.button_text << "]";
                if (focused) set_normal();
            }
            else if (f.type == LABEL) {
                std::cout << f.button_text;
            }
            else { // STRING_INPUT or INT_INPUT
                if (focused) set_highlight();

                if (f.type == STRING_INPUT) {
                    std::cout << f.value_str;

                    if (focused) {
                        // ← only when active: draw padding + blinking cursor
                        int len = (int)f.value_str.length();
                        bool show_cursor = (GetTickCount() / 400) % 2;
                        for (int k = len; k < f.max_len; ++k) {
                            std::cout << (k == len && show_cursor ? '_' : ' ');
                        }
                    }
                    else {
                        // ← when inactive: just erase any previous longer text
                        for (int k = (int)f.value_str.length(); k < f.max_len; ++k)
                            std::cout << ' ';
                    }
                }
                else if (f.type == INT_INPUT) {
                    std::string display = f.value_str.empty() ? "0" : f.value_str;
                    std::cout << display;

                    if (focused) {
                        int len = (int)display.length();
                        bool show_cursor = (GetTickCount() / 400) % 2;
                        for (int k = len; k < f.max_len; ++k) {
                            std::cout << (k == len && show_cursor ? '_' : ' ');
                        }
                    }
                    else {
                        for (int k = (int)display.length(); k < f.max_len; ++k)
                            std::cout << ' ';
                    }
                }

                if (focused) set_normal();
            }
        }
    }
    

    void wait(double seconds) {
        std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    }

    int run_ui(FIELDS& fields) { // returns active field
        int active = 0;
        while (!is_focusable(fields[active])) active++; // start on first focusable field
        paint(fields, active);

        int ch, ch2;
        while (_kbhit())_getch(); // clear any keystrokes in the buffer
        while (true) {
            ch = ch2 = 0;
            ch = _getch();
            ch2 = (_kbhit()? _getch(): 0); // if there is a second byte waiting, grab it.
            
            uint16_t CH;
            CH = (static_cast<uint16_t>(ch)<<8) | ch2;

            uint16_t LEFT = (static_cast<uint16_t>(224) << 8) | 75;
            uint16_t RIGHT = (static_cast<uint16_t>(224) << 8) | 77;
            uint16_t UP = (static_cast<uint16_t>(224) << 8) | 72;
            uint16_t DOWN = (static_cast<uint16_t>(224) << 8) | 80;
            // Tried shift-tab -- doesn't work anymore. Don't really need it.

            if (ch == 9 || CH == RIGHT || CH == DOWN) {       // Tab / Right / Down
                move_focus(+1, fields, active);
            }
            else if (CH == LEFT || CH == UP) { // Left / Up
                move_focus(-1, fields, active);
            }
            else if (ch == 27) 
                return active; // Esc
            else if (ch == '\r' && fields[active].type == BUTTON) {
                return active;
            }
            else if (ch == 8) { // Backspace
                auto& f = fields[active];
                if (f.type == STRING_INPUT && !f.value_str.empty()) {
                    f.value_str.pop_back();
                }
                else if (f.type == INT_INPUT && !f.value_str.empty()) {
                    f.value_str.pop_back();  // Just remove last char from string
                }
            }
            else if (ch >= 32 && ch <= 126) { // alpha, digits, symbols
                auto& f = fields[active];
                if (f.type == STRING_INPUT && (int)f.value_str.length() < f.max_len)
                    f.value_str += (char)ch;
                else if (f.type == INT_INPUT) {
                    if ((ch == '-' && f.value_str.empty()) || isdigit(ch)) {
                        if (f.value_str.length() < f.max_len)  // or some reasonable int digit limit
                            f.value_str += (char)ch;
                    }
                }
            }

            paint(fields,active);
        }
    }

#if 0
    int test_ui() {
        std::vector<ui::InputField> fields;
        int active = 0;
        //                row,col, prompt,     , type          , value_str, value_int, maxlen, buttontext

        fields.push_back({ 1,  5, "=== Simple Console Form ===", DISPLAY });
        fields.push_back({ 3,  0, "", DISPLAY }); // empty line

        fields.push_back({ 5,  5, "Name     : ", STRING_INPUT });
        fields.push_back({ 6,  5, "Age      : ", INT_INPUT     ,    "",         0,      3 });
        fields.push_back({ 7,  5, "City     : ", STRING_INPUT,      "",         0,      25 });
        fields.push_back({ 8,  5, "Email    : ", STRING_INPUT,      "",         0,      40 });

        fields.push_back({ 11, 10, "",           BUTTON,            "",         0,      0,  "Accept" });
        fields.push_back({ 11, 25, "",           BUTTON,            "",         0,      0,  "Exit" });

        fields.push_back({ 14, 0, "Tab / arrows = move | Enter = button | Esc = quit", DISPLAY });

        run_ui(fields, active);
        return 0;
    }
#endif
}//namespace ui 

