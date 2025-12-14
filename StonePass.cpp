// Portable version is default on all platforms.
// Uncomment the line below to force the Windows-specific non-portable UI (MSVC only).

//#define USE_NONPORTABLE_WINDOWS_INTERFACE

#include "StonePass.h"

int main() {
	generate_password_interactive();
	return EXIT_SUCCESS;
}
