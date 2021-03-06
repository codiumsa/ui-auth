var gulp = require('gulp');
var concat = require('gulp-concat');
var uglify = require('gulp-uglify');
var rename = require('gulp-rename');
var path = require('path');
var plumber = require('gulp-plumber');
var runSequence = require('run-sequence');
var jshint = require('gulp-jshint');
var babel = require('gulp-babel');

/**
 * File patterns
 **/

// Root directory
var rootDirectory = path.resolve('./');

// Source directory for build process
var sourceDirectory = path.join(rootDirectory, './src');

var sourceFiles = [

  // Make sure module files are handled first
  path.join(sourceDirectory, '/**/*.module.js'),

  // Then add all services files
  path.join(sourceDirectory, '/services/**/*.js'),

  // Then add all directives files
  path.join(sourceDirectory, '/directives/**/*.js')
];

var lintFiles = [
  'gulpfile.js'
].concat(sourceFiles);

gulp.task('build', function() {
  gulp.src(sourceFiles)
    .pipe(plumber())
    .pipe(concat('ui-auth.js'))
    .pipe(babel({
      presets: ['es2015']
    }))
    .pipe(gulp.dest('./dist/'))
    .pipe(uglify())
    .pipe(rename('ui-auth.min.js'))
    .pipe(gulp.dest('./dist'));
});

/**
 * Process
 */
gulp.task('process-all', function(done) {
  runSequence('jshint', 'build', done);
});

/**
 * Validate source JavaScript
 */
gulp.task('jshint', function() {
  return gulp.src(lintFiles)
    .pipe(plumber())
    .pipe(jshint())
    .pipe(jshint.reporter('jshint-stylish'))
    .pipe(jshint.reporter('fail'));
});

gulp.task('default', function() {
  runSequence('process-all');
});
