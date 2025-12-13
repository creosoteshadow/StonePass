#pragma once
// file ui.h -- a simple text-based User Interface toolset
#define _CRT_DECLARE_NONSTDC_NAMES 1
#include <string>
#include <vector>
#include "windows_fix.h"

namespace ui {

    void set_highlight();
    void set_normal();

    enum FieldType { DISPLAY, LABEL, STRING_INPUT, INT_INPUT, BUTTON };

    struct InputField {
        int         row, col; // screen row and column
        std::string prompt;
        FieldType   type = STRING_INPUT;
        std::string value_str;
        int         value_int = 0;
        int         max_len = 30;
        std::string button_text;
    };

    using FIELDS = std::vector<InputField>;

    void gotoxy(int x, int y);
    void cls();

    // Helper: is this field focusable?
    bool is_focusable(const InputField& f);

    // Move focus forward / backward, skipping DISPLAY fields
    void move_focus(int direction, FIELDS& fields, int& active);

    void paint(FIELDS& fields, int active);
    int run_ui(FIELDS& fields);

    //int test_ui();
}

