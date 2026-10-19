#include <stdio.h>

// Icon-preservation fixture: a console EXE that carries an embedded icon.
// The packer must keep the Explorer icon identical after protection, even
// when resource protection encrypts the whole .rsrc section.
int main() {
    printf("ICON-FIXTURE-OK\n");
    return 0;
}
