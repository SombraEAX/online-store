export default defineNuxtConfig({
  ssr: false,
  app: {
    head: {
      title: 'Company',
      htmlAttrs: {
        lang: 'en'
      },
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { hid: 'description', name: 'description', content: 'Company' }
      ],
      link: [
        { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
      ]
    }
  },
  components: false,
  css: [
    './assets/css/fonts.css'
  ],
  modules: [
    '@nuxtjs/color-mode'
  ],
  watchers: {
    chokidar: {
      ignoreInitial: true,
      ignored: [/node_modules/, /\.nuxt/, /node_modules\.bak/]
    }
  },
  vite: {
    server: {
      watch: {
        ignored: [/node_modules/, /\.nuxt/, /node_modules\.bak/]
      }
    }
  }
})
