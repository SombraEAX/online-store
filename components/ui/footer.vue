<template lang="pug">
	.footer
		nuxt-link.footer-link(v-for="link in links" :key="link.url" :to="link.url") {{link.title}}
		.footer-placeholder
		.footer-copy Company ltd &copy;
</template>
<style lang="scss" scoped>
.footer{
	background:#000099;
	padding:20px;
	display:flex;
	align-items:center
}
.footer-copy{
	color:#fff
}
.footer-placeholder{
	flex:1
}
.footer-link{
	color:#fff;
	text-decoration:none;
	margin-right:20px
}
.footer-link:hover{
	text-decoration:underline		
}
@media (max-width: 550px) {
	.footer{
		display:none
	}
}
</style>
<script>
	export default {
		data(){
			return {
				links:[
					{url:'/',title:'Home'},
					{url:'/catalog/',title:'Catalog'},
					{url:'/contacts',title:'Contacts'}
				]
			}
		}
	}
</script>
