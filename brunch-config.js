const autoprefixer = require('autoprefixer');


module.exports = {
  paths: {
    public: 'static'
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
      manifest: 'src/server/resources/manifest.json',
      autoClearOldFiles: true,
      // srcBasePath: 'static/',
      // destBasePath: 'static/',
      // publicRootPath: '/static'
    }
  }
}
