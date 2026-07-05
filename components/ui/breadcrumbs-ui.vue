<template lang="pug">
	.breadcrumbs-wrapper
		nuxt-link.breadcrumbs-back(v-if="parentUrl" :to="parentUrl") ← {{parentCaption}}
		.breadcrumbs
			.breadcrumb
				nuxt-link(to="/") Home
			.breadcrumb(v-for="breadcrumb in breadcrumbs")
				| !{' » '}
				nuxt-link(:to="breadcrumb.url") {{breadcrumb.caption}}
</template>
<style scoped lang="scss">
.breadcrumbs-back {
	display: none;
	padding: 10px 0;
	color: #888;
	text-decoration: none;
}
.breadcrumb{
	display:inline
}
.breadcrumb a{
	color:#888;
	text-decoration:none
}
.breadcrumb a:hover{
	text-decoration:underline
}
@media (max-width: 500px) {
	.breadcrumbs {
		display: none;
	}
	.breadcrumbs-back {
		display: block;
	}
}
</style>
<script>
	export default {
		props: ['breadcrumbs'],
		computed: {
			parentUrl() {
				if (!this.breadcrumbs || !this.breadcrumbs.length) return null
				if (this.breadcrumbs.length === 1) return '/'
				return this.breadcrumbs[this.breadcrumbs.length - 2].url
			},
			parentCaption() {
				if (!this.breadcrumbs || !this.breadcrumbs.length) return null
				if (this.breadcrumbs.length === 1) return 'Home'
				return this.breadcrumbs[this.breadcrumbs.length - 2].caption
			}
		}
	}
</script>
