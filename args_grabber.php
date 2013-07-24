<?php
/**
 * Граббер для поисковика параметров
 *
 * @author Beched <Ahack.Ru>
 * @copyright Hack4Sec-team <hack4sec.team@gmail.com> 2011
 * @link http://hack4sec.blogspot.com/
 * @license http://www.gnu.org/licenses/gpl-2.0.html
 */

if( $_SERVER[ 'argc' ] != 2 ) die( 'Usage: php args_grabber.php /path/to/dir/with/php/sources' );

function rglob( $dir, $pattern = '*', $flags = 0 ) {
        $paths = glob( $dir . DIRECTORY_SEPARATOR . '*', GLOB_MARK | GLOB_ONLYDIR | GLOB_NOSORT );
        $files = glob( $dir . DIRECTORY_SEPARATOR . $pattern, $flags );
        foreach ( $paths as $path ) {
            if( $path != '.' && $path != '..' )
                $files = array_merge( $files, rglob( $path, $pattern, $flags ) );
        }
        return $files;
}

print( "============================\nBrowsing files...\n" );
$files = rglob( $_SERVER[ 'argv' ][ 1 ], '*.php' );
print( "============================\nFound " . count( $files ) . " files.\nNow parsing files to find parameters...\n" );

$params = array();
foreach( $files as $name ) {
    preg_match_all( '#(GET|POST|COOKIE)\[(\'|\")?([^\$](\w)*)(\'|\')?\]#Usi', file_get_contents( $name ), $matches );
    $params = array_merge( $params, $matches[ 3 ] );
}

print( "============================\nGrabbed " . count( $params ) . " parameters.\n" );

$all = array_map( 'trim', file( '../bases/argsbase.txt' ) );

$params = array_unique( array_merge( $all, array_map( function( $val ) {
    return trim( $val, ' \'"');
}, $params ) ) );

file_put_contents( '../bases/argsbase.txt', '' );
print( "============================\nRemoved duplicates, now " . count( $params ) . " parameters in base.\n" );

foreach( $params as $param)
    file_put_contents( '../bases/argsbase.txt', trim( $param, ' \'"' ) . "\n", FILE_APPEND );