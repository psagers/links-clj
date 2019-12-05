const autoprefixer = require('autoprefixer');


module.exports = {
  paths: {
    public: 'resources/public'
  },

  files: {
    stylesheets: {
      joinTo: 'links.css'
    }
  },

  plugins: {
    sass: {
      mode: 'native'
    },

    postcss: {
      processors: [autoprefixer({grid: 'autoplace'})]
    },

    fingerprint: {
      manifest: 'resources/links/manifest.json',
      autoClearOldFiles: true,
      srcBasePath: 'resources/public/',
      destBasePath: 'resources/public/',
    }
  }
}
