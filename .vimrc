" indentation rules for HIPL: 4 spaces, no tabs
set expandtab
set shiftwidth=4
set softtabstop=4

autocmd FileType make,automake set noexpandtab shiftwidth=8 softtabstop=8

" trailing whitespace is forbidden, so highlight it
let c_space_errors = 1

if filereadable(".vimrc_custom")
    source .vimrc_custom
endif
