<template lang="pug">
	.global-wrapper
		site-header
		.page
			slot
		site-footer
</template>

<script>
	import SiteHeader from './header.vue'
	import SiteFooter from './footer.vue'

	export default {
		components:{
			SiteHeader,
			SiteFooter
		},
		name: 'index'
	}
</script>

<style lang="scss" scoped>
.global-wrapper{
	display:flex;
	flex-direction:column;
	min-height:100vh;
}
.page{
	margin-left:10vw;
	margin-right:10vw;
	flex:1;
	margin-top:20px;
	margin-bottom:20px
}
@media (max-width: 800px) {
	.page{
		margin-left:30px;
		margin-right:30px
	}
}
@media (max-width: 500px) {
	.page{
		margin-left:10px;
		margin-right:10px
	}
}
</style>
